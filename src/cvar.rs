use crate::remote;
use std::marker::PhantomData;
use std::mem::offset_of;
use windows::Win32::Foundation::HANDLE;

//--------------------------------------------------------------------------------------------------

/// CCVar in tier0.dll, implements VEngineCvar007.
#[repr(C)]
pub struct CCVar {
	// The variable list stores pointers to the data, whereas the command list
	// stores the data inline. For our purposes this means that each variable will need a
	// separate remote memory read.
	_0x00: [u8; 0x40],
	pub vars: List<*const Var>,
	_0x58: [u8; 0xA0],
	pub cmds: List<Cmd>,
	// etc...
}

/// Data for a convar.
#[repr(C)]
pub struct Var {
	pub name: *const u8,
	_0x08: [u8; 0x28],
	pub flags: u64,
	// etc...
}

/// Data for a concommand.
#[repr(C)]
pub struct Cmd {
	pub name: *const u8,
	_0x08: [u8; 0x08],
	pub flags: u64,
	_0x18: [u8; 0x18],
}

//--------------------------------------------------------------------------------------------------

/// Linked list structure that's used for cvar registrations.
/// Nodes are stored in a flat array and are referred to by index.
#[repr(C)]
pub struct List<Data> {
	count: u16,
	flags: u16,
	nodes_ptr: usize,
	head: u16,
	_marker: PhantomData<Data>,
}

/// Linked list node.
#[repr(C)]
pub struct Node<Data> {
	data: Data,
	prev: u16,
	next: u16,
}

/// Index used as a `null` value for node references.
const NULL_NODE: u16 = 0xFFFF;

pub struct LocalList<Data> {
	nodes: Box<[Node<Data>]>,
	remote_nodes: usize,
	head: u16,
}

pub struct ListIterator<'a, Data> {
	nodes: &'a [Node<Data>],
	next: u16,
}

impl<Data> List<Data> {
	/// Reads the entire list into memory.
	pub fn read(&self, process: HANDLE) -> windows::core::Result<LocalList<Data>> {
		// If this condition is false then the node indices are relative to zero instead
		// of the stored nodes array. This doesn't really make sense, and I haven't seen
		// it ever happen, but the game code seems to do it so I'm replicating it here.
		let real_nodes_ptr = if (self.flags & 0x7FFF) != 0 {
			self.nodes_ptr
		} else {
			0
		};

		let nodes = remote::read_array(process, real_nodes_ptr, self.count as usize)?;

		Ok(LocalList {
			nodes,
			remote_nodes: self.nodes_ptr,
			head: self.head,
		})
	}
}

impl<Data> LocalList<Data> {
	const DATA_OFFSET: usize = offset_of!(Node<Data>, data);

	/// Converts a node data pointer from a local address to a remote address.
	/// The given pointer MUST point to data in this list, not a copy.
	pub fn to_remote(&self, data: *const Data) -> *const Data {
		let node = data.wrapping_byte_sub(Self::DATA_OFFSET).cast();
		assert!(self.nodes.as_ptr_range().contains(&node));
		let node_offset = unsafe { node.byte_offset_from_unsigned(self.nodes.as_ptr()) };
		(self.remote_nodes + node_offset + Self::DATA_OFFSET) as _
	}
}

impl<'a, Data> IntoIterator for &'a LocalList<Data> {
	type Item = &'a Data;
	type IntoIter = ListIterator<'a, Data>;

	fn into_iter(self) -> Self::IntoIter {
		ListIterator {
			nodes: &self.nodes,
			next: self.head,
		}
	}
}

impl<'a, Data> Iterator for ListIterator<'a, Data> {
	type Item = &'a Data;

	fn next(&mut self) -> Option<Self::Item> {
		if self.next == NULL_NODE {
			// End of the line.
			None
		} else {
			let node = &self.nodes[self.next as usize];
			self.next = node.next;
			Some(&node.data)
		}
	}
}
