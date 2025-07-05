# Generated script file by Il2CppInspectorRedux - https://github.com/LukeFZ (Original Il2CppInspector by http://www.djkaty.com - https://github.com/djkaty)
# Target Unity version: 2021.2.0 - 2021.2.99

import json
import os
from datetime import datetime
import abc

class BaseStatusHandler(abc.ABC):
	def initialize(self): pass
	def shutdown(self): pass

	def update_step(self, name: str, max_items: int = 0): print(name)
	def update_progress(self, progress: int = 1): pass

	def was_cancelled(self): return False

class BaseDisassemblerInterface(abc.ABC):
	supports_fake_string_segment: bool = False

	@abc.abstractmethod
	def get_script_directory(self) -> str: return ""

	@abc.abstractmethod
	def on_start(self): pass

	@abc.abstractmethod
	def on_finish(self): pass

	@abc.abstractmethod
	def define_function(self, address: int, end: int | None = None): pass

	@abc.abstractmethod
	def define_data_array(self, address: int, type: str, count: int): pass

	@abc.abstractmethod
	def set_data_type(self, address: int, type: str): pass

	@abc.abstractmethod
	def set_function_type(self, address: int, type: str): pass

	@abc.abstractmethod
	def set_data_comment(self, address: int, cmt: str): pass

	@abc.abstractmethod
	def set_function_comment(self, address: int, cmt: str): pass

	@abc.abstractmethod
	def set_data_name(self, address: int, name: str): pass

	@abc.abstractmethod
	def set_function_name(self, address: int, name: str): pass

	@abc.abstractmethod
	def add_cross_reference(self, from_address: int, to_address: int): pass

	@abc.abstractmethod
	def import_c_typedef(self, type_def: str): pass

	# optional
	def add_function_to_group(self, address: int, group: str): pass
	def cache_function_types(self, function_types: list[str]): pass

	# only required if supports_fake_string_segment == True
	def create_fake_segment(self, name: str, size: int) -> int: return 0

	def write_string(self, address: int, value: str) -> int: pass
	def write_address(self, address: int, value: int): pass

class ScriptContext:
	_backend: BaseDisassemblerInterface
	_status: BaseStatusHandler

	def __init__(self, backend: BaseDisassemblerInterface, status: BaseStatusHandler) -> None:
		self._backend = backend
		self._status = status

	def from_hex(self, addr: str): 
		return int(addr, 0)

	def parse_address(self, d: dict): 
		return self.from_hex(d['virtualAddress'])

	def define_il_method(self, definition: dict):
		addr = self.parse_address(definition)
		self._backend.set_function_name(addr, definition['name'])
		self._backend.set_function_type(addr, definition['signature'])
		self._backend.set_function_comment(addr, definition['dotNetSignature'])
		self._backend.add_function_to_group(addr, definition['group'])

	def define_il_method_info(self, definition: dict):
		addr = self.parse_address(definition)
		self._backend.set_data_type(addr, r'struct MethodInfo *')
		self._backend.set_data_name(addr, definition['name'])
		self._backend.set_data_comment(addr, definition['dotNetSignature'])
		if 'methodAddress' in definition:
			method_addr = self.from_hex(definition["methodAddress"])
			self._backend.add_cross_reference(method_addr, addr)
			
	def define_cpp_function(self, definition: dict):
		addr = self.parse_address(definition)
		self._backend.set_function_name(addr, definition['name'])
		self._backend.set_function_type(addr, definition['signature'])

	def define_string(self, definition: dict):
		addr = self.parse_address(definition)
		self._backend.set_data_type(addr, r'struct String *')
		self._backend.set_data_name(addr, definition['name'])
		self._backend.set_data_comment(addr, definition['string'])

	def define_field(self, addr: str, name: str, type: str, il_type: str | None = None):
		address = self.from_hex(addr)
		self._backend.set_data_type(address, type)
		self._backend.set_data_name(address, name)
		if il_type is not None:
			self._backend.set_data_comment(address, il_type)

	def define_field_from_json(self, definition: dict):
		self.define_field(definition['virtualAddress'], definition['name'], definition['type'], definition['dotNetType'])

	def define_array(self, definition: dict):
		addr = self.parse_address(definition)
		self._backend.define_data_array(addr, definition['type'], int(definition['count']))
		self._backend.set_data_name(addr, definition['name'])

	def define_field_with_value(self, definition: dict):
		addr = self.parse_address(definition)
		self._backend.set_data_name(addr, definition['name'])
		self._backend.set_data_comment(addr, definition['value'])

	def process_metadata(self, metadata: dict):
		# Function boundaries
		function_addresses = metadata['functionAddresses']
		function_addresses.sort()
		count = len(function_addresses)

		self._status.update_step('Processing function boundaries', count)
		for i in range(count):
			start = self.from_hex(function_addresses[i])
			if start == 0:
				self._status.update_progress()
				continue

			end = self.from_hex(function_addresses[i + 1]) if i + 1 != count else None

			self._backend.define_function(start, end)
			self._status.update_progress()

		# Method definitions
		self._status.update_step('Processing method definitions', len(metadata['methodDefinitions']))
		self._backend.cache_function_types([x["signature"] for x in metadata['methodDefinitions']])
		for d in metadata['methodDefinitions']:
			self.define_il_method(d)
			self._status.update_progress()
		
		# Constructed generic methods
		self._status.update_step('Processing constructed generic methods', len(metadata['constructedGenericMethods']))
		self._backend.cache_function_types([x["signature"] for x in metadata['constructedGenericMethods']])
		for d in metadata['constructedGenericMethods']:
			self.define_il_method(d)
			self._status.update_progress()

		# Custom attributes generators
		self._status.update_step('Processing custom attributes generators', len(metadata['customAttributesGenerators']))
		self._backend.cache_function_types([x["signature"] for x in metadata['customAttributesGenerators']])
		for d in metadata['customAttributesGenerators']:
			self.define_cpp_function(d)
			self._status.update_progress()
		
		# Method.Invoke thunks
		self._status.update_step('Processing Method.Invoke thunks', len(metadata['methodInvokers']))
		self._backend.cache_function_types([x["signature"] for x in metadata['methodInvokers']])
		for d in metadata['methodInvokers']:
			self.define_cpp_function(d)
			self._status.update_progress()

		# String literals for version >= 19
		if 'virtualAddress' in metadata['stringLiterals'][0]:
			self._status.update_step('Processing string literals (V19+)', len(metadata['stringLiterals']))

			if self._backend.supports_fake_string_segment:
				total_string_length = 0
				for d in metadata['stringLiterals']:
					total_string_length += len(d["string"]) + 1
				
				aligned_length = total_string_length + (4096 - (total_string_length % 4096))
				segment_base = self._backend.create_fake_segment(".fake_strings", aligned_length)

				current_string_address = segment_base
				for d in metadata['stringLiterals']:
					self.define_string(d)

					ref_addr = self.parse_address(d)
					written_string_length = self._backend.write_string(current_string_address, d["string"])
					self._backend.set_data_type(ref_addr, r'const char* const')
					self._backend.write_address(ref_addr, current_string_address)

					current_string_address += written_string_length
					self._status.update_progress()
			else:
				for d in metadata['stringLiterals']:
					self.define_string(d)
					self._status.update_progress()

		# String literals for version < 19
		else:
			self._status.update_step('Processing string literals (pre-V19)')
			litDecl = 'enum StringLiteralIndex {\n'
			for d in metadata['stringLiterals']:
				litDecl += "  " + d['name'] + ",\n"
			litDecl += '};\n'

			self._backend.import_c_typedef(litDecl)
		
		# Il2CppClass (TypeInfo) pointers
		self._status.update_step('Processing Il2CppClass (TypeInfo) pointers', len(metadata['typeInfoPointers']))
		for d in metadata['typeInfoPointers']:
			self.define_field_from_json(d)
			self._status.update_progress()
		
		# Il2CppType (TypeRef) pointers
		self._status.update_step('Processing Il2CppType (TypeRef) pointers', len(metadata['typeRefPointers']))
		for d in metadata['typeRefPointers']:
			self.define_field(d['virtualAddress'], d['name'], r'struct Il2CppType *', d['dotNetType'])
			self._status.update_progress()
		
		# MethodInfo pointers
		self._status.update_step('Processing MethodInfo pointers', len(metadata['methodInfoPointers']))
		for d in metadata['methodInfoPointers']:
			self.define_il_method_info(d)
			self._status.update_progress()

		# FieldInfo pointers, add the contents as a comment
		self._status.update_step('Processing FieldInfo pointers', len(metadata['fields']))
		for d in metadata['fields']:
			self.define_field_with_value(d)
			self._status.update_progress()

		# FieldRva pointers, add the contents as a comment
		self._status.update_step('Processing FieldRva pointers', len(metadata['fieldRvas']))
		for d in metadata['fieldRvas']:
			self.define_field_with_value(d)
			self._status.update_progress()

		# IL2CPP type metadata
		self._status.update_step('Processing IL2CPP type metadata', len(metadata['typeMetadata']))
		for d in metadata['typeMetadata']:
			self.define_field(d['virtualAddress'], d['name'], d['type'])
		
		# IL2CPP function metadata
		self._status.update_step('Processing IL2CPP function metadata', len(metadata['functionMetadata']))
		for d in metadata['functionMetadata']:
			self.define_cpp_function(d)

		# IL2CPP array metadata
		self._status.update_step('Processing IL2CPP array metadata', len(metadata['arrayMetadata']))
		for d in metadata['arrayMetadata']:
			self.define_array(d)

		# IL2CPP API functions
		self._status.update_step('Processing IL2CPP API functions', len(metadata['apis']))
		self._backend.cache_function_types([x["signature"] for x in metadata['apis']])
		for d in metadata['apis']:
			self.define_cpp_function(d)

	def process(self):
		self._status.initialize()

		try:
			start_time = datetime.now()

			self._status.update_step("Running script prologue")
			self._backend.on_start()

			metadata_path = os.path.join(self._backend.get_script_directory(), "./il2cpp_binaryninja.json")
			with open(metadata_path, "r") as f:
				self._status.update_step("Loading JSON metadata")
				metadata = json.load(f)['addressMap']
				self.process_metadata(metadata)

			self._status.update_step("Running script epilogue")
			self._backend.on_finish()

			self._status.update_step('Script execution complete.')

			end_time = datetime.now()
			print(f"Took: {end_time - start_time}")

		except RuntimeError: 
			pass
		
		finally: 
			self._status.shutdown()
from binaryninja import *

#try:
#	from typing import TYPE_CHECKING
#	if TYPE_CHECKING:
#		from ..shared_base import BaseStatusHandler, BaseDisassemblerInterface, ScriptContext
#		import json
#		import os
#		import sys
#		from datetime import datetime
#		from typing import Literal
#		bv: BinaryView = None # type: ignore
#except:
#	pass

CURRENT_PATH = os.path.dirname(os.path.realpath(__file__))

class BinaryNinjaDisassemblerInterface(BaseDisassemblerInterface):
	# this is implemented, 
	# however the write API does not seem to work properly here (possibly a bug), 
	# so this is disabled for now
	supports_fake_string_segment: bool = False

	_status: BaseStatusHandler
	
	_view: BinaryView
	_undo_id: str
	_components: dict[str, Component]
	_type_cache: dict[str, Type]
	_function_type_cache: dict[str, Type]

	_address_size: int
	_endianness: Literal["little", "big"]

	TYPE_PARSER_OPTIONS = [
		"--target=x86_64-pc-linux",
		"-x", "c++",
		"-D_BINARYNINJA_=1"
	]

	def __init__(self, status: BaseStatusHandler):
		self._status = status

	def _get_or_create_type(self, type: str) -> Type:
		if type.startswith("struct "):
			type = type[len("struct "):]
		elif type.startswith("class "):
			type = type[len("class "):]

		if type in self._type_cache:
			return self._type_cache[type]
		
		if type.endswith("*"):
			base_type = self._get_or_create_type(type[:-1].strip())

			parsed = PointerType.create(self._view.arch, base_type)  # type: ignore
		else:
			parsed = self._view.get_type_by_name(type)
			if parsed is None:
				parsed, errors = self._view.parse_type_string(type)

		self._type_cache[type] = parsed
		return parsed

	def _parse_type_source(self, types: str, filename: str | None = None):
		parsed_types, errors = TypeParser.default.parse_types_from_source(
			types,
			filename if filename else "types.hpp",
			self._view.platform if self._view.platform is not None else Platform["windows-x86_64"],
			self._view,
			self.TYPE_PARSER_OPTIONS
		)

		if parsed_types is None:
			log_error("Failed to import types.")
			log_error(errors)
			return None
		
		return parsed_types

	def get_script_directory(self) -> str:
		return CURRENT_PATH

	def on_start(self):
		self._view = bv # type: ignore
		self._undo_id = self._view.begin_undo_actions()
		self._view.set_analysis_hold(True)
		self._components = {}
		self._type_cache = {}
		self._function_type_cache = {}

		self._address_size = self._view.address_size
		self._endianness = "little" if self._view.endianness == Endianness.LittleEndian else "big"
		
		self._status.update_step("Parsing header")

		with open(os.path.join(self.get_script_directory(), "il2cpp.h"), "r") as f:
			parsed_types = self._parse_type_source(f.read(), "il2cpp.hpp")
			if parsed_types is None:
				return

		self._status.update_step("Importing header types", len(parsed_types.types))

		def import_progress_func(progress: int, total: int):
			self._status.update_progress(1)
			return True

		self._view.define_user_types([(x.name, x.type) for x in parsed_types.types], import_progress_func)

	def on_finish(self):
		self._view.commit_undo_actions(self._undo_id)
		self._view.set_analysis_hold(False)
		self._view.update_analysis()

	def define_function(self, address: int, end: int | None = None):
		if self._view.get_function_at(address) is not None:
			return
		
		self._view.create_user_function(address)

	def define_data_array(self, address: int, type: str, count: int):
		parsed_type = self._get_or_create_type(type)
		array_type = ArrayType.create(parsed_type, count)
		var = self._view.get_data_var_at(address)
		if var is None:
			self._view.define_user_data_var(address, array_type)
		else:
			var.type = array_type

	def set_data_type(self, address: int, type: str):
		var = self._view.get_data_var_at(address)
		dtype = self._get_or_create_type(type)
		if var is None:
			self._view.define_user_data_var(address, dtype)
		else:
			var.type = dtype

	def set_function_type(self, address: int, type: str):
		function = self._view.get_function_at(address)
		if function is None:
			return
		
		if type in self._function_type_cache:
			function.type = self._function_type_cache[type] # type: ignore
		else:
			#log_info(f"skipping function type setting for {address}, {type}")
			#pass
			function.type = type.replace("this", "`this`")

	def set_data_comment(self, address: int, cmt: str):
		self._view.set_comment_at(address, cmt)

	def set_function_comment(self, address: int, cmt: str):
		function = self._view.get_function_at(address)
		if function is None:
			return

		function.comment = cmt	

	def set_data_name(self, address: int, name: str):
		var = self._view.get_data_var_at(address)
		if var is None:
			return
		
		if name.startswith("_Z"):
			type, demangled = demangle_gnu3(self._view.arch, name, self._view)
			var.name = get_qualified_name(demangled)
		else:
			var.name = name

	def set_function_name(self, address: int, name: str):
		function = self._view.get_function_at(address)
		if function is None:
			return

		if name.startswith("_Z"):
			type, demangled = demangle_gnu3(self._view.arch, name, self._view)
			function.name = get_qualified_name(demangled)
			#function.type = type - this does not work due to the generated types not being namespaced. :(
		else:
			function.name = name

	def add_cross_reference(self, from_address: int, to_address: int):
		self._view.add_user_data_ref(from_address, to_address)

	def import_c_typedef(self, type_def: str): 
		self._view.define_user_type(None, type_def)

	# optional
	def _get_or_create_component(self, name: str):
		if name in self._components:
			return self._components[name]
	
		current = name
		if current.count("/") != 0:
			split_idx = current.rindex("/")
			parent, child = current[:split_idx], current[split_idx:]
			parent = self._get_or_create_component(name)
			component = self._view.create_component(child, parent)
		else:
			component = self._view.create_component(name)

		self._components[name] = component
		return component

	def add_function_to_group(self, address: int, group: str):
		return
		function = self._view.get_function_at(address)
		if function is None:
			return
		
		self._get_or_create_component(group).add_function(function)

	def cache_function_types(self, signatures: list[str]):
		function_sigs = set(signatures)
		if len(function_sigs) == 0:
			return
		
		typestr = ";\n".join(function_sigs).replace("this", "_this") + ";"
		parsed_types = self._parse_type_source(typestr, "cached_types.hpp")
		if parsed_types is None:
			return

		# bv.parse_types_from_source returns a dict in the functions field.
		# TypeParser.parse_types_from_source does not.
		for function_sig, function in zip(function_sigs, parsed_types.functions):
			self._function_type_cache[function_sig] = function.type

	# only required if supports_fake_string_segment == True
	def create_fake_segment(self, name: str, size: int) -> int: 
		last_end_addr = self._view.mapped_address_ranges[-1].end
		if last_end_addr % 0x1000 != 0: 
			last_end_addr += (0x1000 - (last_end_addr % 0x1000))

		self._view.add_user_segment(last_end_addr, size, 0, 0, SegmentFlag.SegmentContainsData)
		self._view.add_user_section(name, last_end_addr, size, SectionSemantics.ReadOnlyDataSectionSemantics)
		return last_end_addr
	
	def write_string(self, address: int, value: str) -> int:
		encoded = value.encode() + b"\x00"
		self._view.write(address, encoded)
		return len(encoded)

	def write_address(self, address: int, value: int):
		self._view.write(address, value.to_bytes(self._address_size, self._endianness))


class BinaryNinjaStatusHandler(BaseStatusHandler):
	def __init__(self, thread: BackgroundTaskThread):
		self.step = "Initializing"
		self.max_items = 0
		self.current_items = 0
		self.start_time = datetime.now()
		self.step_start_time = self.start_time
		self.last_updated_time = datetime.min
		self._thread = thread
	
	def initialize(self): pass

	def update(self):
		if self.was_cancelled():
			raise RuntimeError("Cancelled script.")

		current_time = datetime.now()
		if 0.5 > (current_time - self.last_updated_time).total_seconds():
			return

		self.last_updated_time = current_time

		step_time = current_time - self.step_start_time
		total_time = current_time - self.start_time
		self._thread.progress = f"Processing IL2CPP metadata: {self.step} ({self.current_items}/{self.max_items}), elapsed: {step_time} ({total_time})"

	def update_step(self, step, max_items = 0):
		self.step = step
		self.max_items = max_items
		self.current_items = 0
		self.step_start_time = datetime.now()
		self.last_updated_time = datetime.min
		self.update()

	def update_progress(self, new_progress = 1):
		self.current_items += new_progress
		self.update()

	def was_cancelled(self): return False

	def close(self):
		pass

# Entry point
class Il2CppTask(BackgroundTaskThread):
	def __init__(self):
		BackgroundTaskThread.__init__(self, "Processing IL2CPP metadata...", False)

	def run(self):
		status = BinaryNinjaStatusHandler(self)
		backend = BinaryNinjaDisassemblerInterface(status)
		context = ScriptContext(backend, status)
		context.process()

Il2CppTask().start()