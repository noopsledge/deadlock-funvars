use anyhow::{Context, bail};
use std::alloc::{Layout, alloc, dealloc};
use std::cmp::Ordering;
use std::ffi::CStr;
use std::mem::MaybeUninit;
use std::range::Range;
use std::slice;
use windows::{
	Win32::Foundation::*,
	Win32::System::Diagnostics::Debug::*,
	Win32::System::Diagnostics::ToolHelp::*,
	Win32::System::SystemServices::*,
	Win32::System::Threading::*,
	core::{Owned, PCWSTR, w},
};

unsafe extern "C" {
	fn _wcsicmp(string1: *const u16, string2: *const u16) -> i32; 
}

fn main() -> anyhow::Result<()> {
	let process;
	let dll_range;

	unsafe {
		let pid = match find_process(w!("deadlock.exe")) {
			Ok(pid) => pid,
			Err(e) => {
				// Give a nicer error message in the case where the process isn't found because
				// this is likely to happen and ERROR_NO_MORE_FILES is a bit cryptic on its own.
				if e.code() == ERROR_NO_MORE_FILES.into() {
					bail!("Unable to find the game process, is it definitely running?");
				} else {
					return Err(e).context("Unexpected error when looking for the game process.");
				}
			}
		};

		dll_range = find_module(pid, w!("tier0.dll"))
			.context("Failed to find tier0.dll in the game process.")?;

		process = Owned::new(
			OpenProcess(
				PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
				false,
				pid,
			)
			.context("Failed to open the game process.")?,
		);
	}

	// Read the entire DLL in one go to avoid needing to jump around with lots of
	// little reads.
	let dll_data = RemoteMemory::new(*process, dll_range)
		.context("Failed to read the dll data.")?;

	let exports = unsafe {
		let exports_ptr = ImageDirectoryEntryToData(
			dll_data.local_ptr as _,
			true,
			IMAGE_DIRECTORY_ENTRY_EXPORT,
			MaybeUninit::uninit().as_mut_ptr(),
		);
		if exports_ptr.is_null() {
			bail!("Failed to find the dll export table.");
		}
		&*(exports_ptr as *const IMAGE_EXPORT_DIRECTORY)
	};

	const MOV_R9_MEM: [u8; 3] = [0x4C, 0x8B, 0x0D];
	const LEA_RAX_MEM: [u8; 3] = [0x48, 0x8D, 0x05];

	let create_interface = find_export(&dll_data, exports, c"CreateInterface")
		.context("Failed to find the CreateInterface function")?;
	let reg_list = get_addr_operand(&dll_data, create_interface, &MOV_R9_MEM)
		.context("Failed to get the interface registration list.")?;
	let cvars_factory = find_interface_factory(&dll_data, reg_list, c"VEngineCvar007")
		.context("Failed to find the factory for the VEngineCvar007 interface.")?;
	let cvars = get_addr_operand(&dll_data, cvars_factory, &LEA_RAX_MEM)
		.context("Failed to get the address of the VEngineCvar007 instance.")?;

	let count = patch_vars(&dll_data, *process, cvars).context("Failed to patch convars.")?;
	println!("Successfully patched {} convars.", count);

	Ok(())
}

/// Gets a process identifier from its name.
unsafe fn find_process(name: PCWSTR) -> windows::core::Result<u32> {
	unsafe {
		let snapshot = Owned::new(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)?);
		let mut process = PROCESSENTRY32W {
			dwSize: size_of::<PROCESSENTRY32W>() as u32,
			..Default::default()
		};
		Process32FirstW(*snapshot, &mut process)?;
		loop {
			if _wcsicmp(name.as_ptr(), process.szExeFile.as_ptr()) == 0 {
				break Ok(process.th32ProcessID);
			}
			Process32NextW(*snapshot, &mut process)?;
		}
	}
}

/// Gets the address range of a loaded module by name.
unsafe fn find_module(pid: u32, name: PCWSTR) -> windows::core::Result<Range<usize>> {
	unsafe {
		let snapshot = Owned::new(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid)?);
		let mut module = MODULEENTRY32W {
			dwSize: size_of::<MODULEENTRY32W>() as u32,
			..Default::default()
		};
		Module32FirstW(*snapshot, &mut module)?;
		loop {
			if _wcsicmp(name.as_ptr(), module.szModule.as_ptr()) == 0 {
				let start = module.modBaseAddr as usize;
				let end = start + module.modBaseSize as usize;
				break Ok(Range { start, end });
			}
			Module32NextW(*snapshot, &mut module)?;
		}
	}
}

/// Reads a single value from a process's address space.
fn remote_read<T>(process: HANDLE, addr: usize) -> windows::core::Result<T> {
	unsafe {
		let mut buffer = MaybeUninit::uninit();
		ReadProcessMemory(
			process,
			addr as _,
			buffer.as_mut_ptr() as _,
			size_of::<T>(),
			None,
		)?;
		Ok(buffer.assume_init())
	}
}

/// Writes a single value to a process's address space.
fn remote_write<T>(process: HANDLE, addr: usize, value: T) -> windows::core::Result<()> {
	unsafe {
		WriteProcessMemory(
			process,
			addr as _,
			&raw const value as _,
			size_of::<T>(),
			None,
		)
	}
}

/// Reads a large chunk of memory from another process and keeps enough state to
/// map addresses between processes.
struct RemoteMemory {
	local_ptr: *mut u8,
	size: usize,
	remote_base: usize,
}

impl RemoteMemory {
	const ALIGN: usize = 16;

	fn new(process: HANDLE, range: Range<usize>) -> windows::core::Result<RemoteMemory> {
		let size = range.end - range.start;
		let layout = Layout::from_size_align(size, Self::ALIGN).unwrap();
		unsafe {
			// The memory is manually allocated so that we can control the alignment.
			let remote_mem = RemoteMemory {
				local_ptr: alloc(layout),
				size,
				remote_base: range.start,
			};
			ReadProcessMemory(
				process,
				remote_mem.remote_base as _,
				remote_mem.local_ptr as _,
				size,
				None,
			)?;
			Ok(remote_mem)
		}
	}

	/// Whether it's valid to read an array of `count` instances of `T` from `rva`.
	/// This will ensure that the buffer we have is suitably sized and aligned.
	fn can_read<T>(&self, rva: usize, count: usize) -> bool {
		align_of::<T>() <= Self::ALIGN
			&& rva & (align_of::<T>() - 1) == 0
			&& rva < self.size
			&& self.size - rva >= size_of::<T>() * count
	}

	/// Gets a reference to an instance of `T` at offset `rva`.
	fn get<T>(&self, rva: usize) -> Option<&T> {
		if self.can_read::<T>(rva, 1) {
			Some(unsafe { &*(self.local_ptr.add(rva) as *const T) })
		} else {
			None
		}
	}

	/// Gets a slice of `count` instances of `T` at offset `rva`.
	fn get_array<T>(&self, rva: usize, count: usize) -> Option<&[T]> {
		if self.can_read::<T>(rva, count) {
			Some(unsafe { slice::from_raw_parts(self.local_ptr.add(rva) as _, count) })
		} else {
			None
		}
	}

	/// Converts an absolute remote address to a relative offset.
	fn get_rva(&self, remote_addr: usize) -> Option<usize> {
		remote_addr.checked_sub(self.remote_base)
	}

	/// Converts a remote pointer to a local reference.
	fn from_remote<T>(&self, ptr: *const T) -> Option<&T> {
		let rva = self.get_rva(ptr as usize)?;
		self.get(rva)
	}

	/// Converts a remote pointer to a local slice.
	fn from_remote_array<T>(&self, ptr: *const T, count: usize) -> Option<&[T]> {
		let rva = self.get_rva(ptr as usize)?;
		self.get_array(rva, count)
	}
}

impl Drop for RemoteMemory {
	fn drop(&mut self) {
		unsafe {
			// Layout is known to be valid from `new()`.
			let layout = Layout::from_size_align_unchecked(self.size, Self::ALIGN);
			dealloc(self.local_ptr, layout);
		}
	}
}

/// Gets the RVA of an exported function by name.
fn find_export(
	image: &RemoteMemory,
	exports: &IMAGE_EXPORT_DIRECTORY,
	name: &CStr,
) -> Option<usize> {
	let name = name.to_bytes_with_nul();
	image
		.get_array::<u32>(
			exports.AddressOfNames as usize,
			exports.NumberOfNames as usize,
		)?
		.binary_search_by(|&rva| {
			if let Some(name2) = image.get_array(rva as usize, name.len()) {
				name2.cmp(name)
			} else {
				Ordering::Greater
			}
		})
		.ok()
		.and_then(|i| image.get::<u32>(exports.AddressOfFunctions as usize + i * size_of::<u32>()))
		.map(|&rva| rva as usize)
}

/// Gets the RVA of an instruction's rip-relative memory operand.
/// `insn_prefix` should be all of the bytes of the instruction up to the
/// variable offset, which is used to validate that we're looking at the
/// expected instruction.
fn get_addr_operand(image: &RemoteMemory, insn_rva: usize, insn_prefix: &[u8]) -> Option<usize> {
	let prefix_len = insn_prefix.len();
	let insn = image.get_array(insn_rva, prefix_len + size_of::<i32>())?;
	if insn.starts_with(insn_prefix) {
		let rip = insn_rva + insn.len();
		let offset = unsafe { insn.as_ptr().add(prefix_len).cast::<i32>().read_unaligned() };
		rip.checked_add_signed(offset as isize)
	} else {
		None
	}
}

/// Traverses the linked list of interface registrations to find the RVA of the
/// factory function for the interface with the given name.
fn find_interface_factory(image: &RemoteMemory, reg_list: usize, name: &CStr) -> Option<usize> {
	#[repr(C)]
	struct RegNode {
		factory: usize,
		name: *const u8,
		next: *const RegNode,
	}

	let name = name.to_bytes_with_nul();
	let head = *image.get::<usize>(reg_list)?;
	let mut node = image.from_remote(head as *const RegNode)?;

	loop {
		let remote_name = image.from_remote_array(node.name, name.len());
		if remote_name == Some(name) {
			// Found it!
			break image.get_rva(node.factory);
		}
		if node.next.is_null() {
			// Reached the end of the list.
			break None;
		}
		node = image.from_remote(node.next)?;
	}
}

/// Patches convar flags to make them show up in game.
fn patch_vars(image: &RemoteMemory, process: HANDLE, cvars: usize) -> windows::core::Result<usize> {
	#[repr(C)]
	struct CVars {
		_0x00: [u8; 0x42],
		flags: u16,
		_0x44: [u8; 0x04],
		buckets_ptr: usize,
		head_index: u16,
	}

	#[repr(C)]
	struct Node {
		data: usize,
		prev: u16,
		next: u16,
	}

	const NULL_NODE: u16 = 0xFFFF;
	const FLAGS_OFFSET: usize = 0x30;
	const FLAG_DEVELOPMENTONLY: u64 = 1 << 1;

	let cvars = image.get::<CVars>(cvars).ok_or(ERROR_PARTIAL_COPY)?;
	let mut node_index = cvars.head_index;
	let mut count = 0;

	if node_index != NULL_NODE {
		// If this condition is false then the bucket indices are relative to zero
		// instead of the stored buckets array. This doesn't really make sense, and I
		// haven't seen it ever happen, but the game code seems to do it so I'm
		// replicating it here.
		let buckets = if (cvars.flags & 0x7FFF) != 0 {
			cvars.buckets_ptr
		} else {
			0
		};

		loop {
			let node_addr = buckets + (node_index as usize) * size_of::<Node>();
			let node = remote_read::<Node>(process, node_addr)?;
			let flags_addr = node.data + FLAGS_OFFSET;
			let mut flags = remote_read::<u64>(process, flags_addr)?;

			if (flags & FLAG_DEVELOPMENTONLY) != 0 {
				// Write back with the flag removed.
				flags &= !FLAG_DEVELOPMENTONLY;
				remote_write(process, flags_addr, flags)?;
				count += 1;
			}

			node_index = node.next;
			if node_index == NULL_NODE {
				break;
			}
		}
	}

	Ok(count)
}
