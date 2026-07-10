use std::alloc::{Layout, alloc, dealloc};
use std::mem::MaybeUninit;
use std::range::Range;
use std::slice;
use windows::{
	Win32::Foundation::*,
	Win32::System::Diagnostics::Debug::*,
};

/// Reads a single value from a process's address space.
pub fn read<T>(process: HANDLE, addr: usize) -> windows::core::Result<T> {
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

/// Reads a dynamically-sized array of values from a process's address space.
pub fn read_array<T>(
	process: HANDLE,
	addr: usize,
	count: usize,
) -> windows::core::Result<Box<[T]>> {
	unsafe {
		let mut buffer = Box::new_uninit_slice(count);
		ReadProcessMemory(
			process,
			addr as _,
			buffer.as_mut_ptr() as _,
			count * size_of::<T>(),
			None,
		)?;
		Ok(buffer.assume_init())
	}
}

/// Writes a single value to a process's address space.
pub fn write<T>(process: HANDLE, addr: usize, value: T) -> windows::core::Result<()> {
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
pub struct Memory {
	local_ptr: *mut u8,
	size: usize,
	remote_base: usize,
}

impl Memory {
	const ALIGN: usize = 16;

	pub fn new(process: HANDLE, range: Range<usize>) -> windows::core::Result<Memory> {
		let size = range.end - range.start;
		let layout = Layout::from_size_align(size, Self::ALIGN).unwrap();
		unsafe {
			// The memory is manually allocated so that we can control the alignment.
			let remote_mem = Memory {
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

	/// Pointer to the data in the local address space.
	pub fn as_ptr(&self) -> *const u8 {
		self.local_ptr
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
	pub fn get<T>(&self, rva: usize) -> Option<&T> {
		if self.can_read::<T>(rva, 1) {
			Some(unsafe { &*(self.local_ptr.add(rva) as *const T) })
		} else {
			None
		}
	}

	/// Gets a slice of `count` instances of `T` at offset `rva`.
	pub fn get_array<T>(&self, rva: usize, count: usize) -> Option<&[T]> {
		if self.can_read::<T>(rva, count) {
			Some(unsafe { slice::from_raw_parts(self.local_ptr.add(rva) as _, count) })
		} else {
			None
		}
	}

	/// Converts an absolute remote address to a relative offset.
	pub fn get_rva(&self, remote_addr: usize) -> Option<usize> {
		remote_addr.checked_sub(self.remote_base)
	}

	/// Converts a remote pointer to a local reference.
	pub fn from_remote<T>(&self, ptr: *const T) -> Option<&T> {
		let rva = self.get_rva(ptr as usize)?;
		self.get(rva)
	}

	/// Converts a remote pointer to a local slice.
	pub fn from_remote_array<T>(&self, ptr: *const T, count: usize) -> Option<&[T]> {
		let rva = self.get_rva(ptr as usize)?;
		self.get_array(rva, count)
	}
}

impl Drop for Memory {
	fn drop(&mut self) {
		unsafe {
			// Layout is known to be valid from `new()`.
			let layout = Layout::from_size_align_unchecked(self.size, Self::ALIGN);
			dealloc(self.local_ptr, layout);
		}
	}
}
