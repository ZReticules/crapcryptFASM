include 'macro\struct.inc'
include 'macro\proc64.inc'

macro table name, parent{
	macro name \{ 
		purge name
		name name#_@ 
	\}
	struc name#_@  \{
	if parent eq
	else
		. parent#_@ 
	end if
}

endt fix }

macro AddTable structure, table{
	struc structure a& \{
		. structure a
		.Table equ table
	\}
}

macro mcall obj_proc*, [args]{
	common
	define _obj_proc obj_proc
	match [obj:prc], _obj_proc\{
		if args eq
			ccall [obj\#.\#prc], addr obj
		else
			ccall [obj\#.\#prc], addr obj, args
		end if
		rept 0\{
	\}
	match obj:prc, _obj_proc\{
		if args eq
			ccall obj\#.\#prc, addr obj
		else
			ccall obj\#.\#prc, addr obj, args
		end if
		rept 0\{
	\}
	match [obj->prc], _obj_proc\{
		From@Table [obj\#.Table:prc], obj, args
		rept 0\{
	\}
	match obj->prc, _obj_proc\{
		From@Table obj\#.Table:prc, obj, args
	\}
}
macro From@Table table_prc, obj, [args]{
	common
	match table:prc, table_prc\{
		if args eq
			ccall table\#.\#prc, addr obj
		else
			ccall table\#.\#prc, addr obj, args
		end if
	\}
}

struc override NewVal{
	store qword NewVal at .
}

macro @this StrucName, reg{
	if reg eq
		virtual at rcx
			.this StrucName
		end virtual
	else 
		mov reg, rcx
		virtual at reg
			.this StrucName
		end virtual
	end if
}

macro @call argum&{
	local _argum, matched
	define _argum argum
	match func=(=), _argum\{
		match =matched obj->proc, matched func\\{
			define matched
			mcall func
		\\}
		match =matched obj:proc, matched func\\{
			define matched
			mcall func
		\\}
		match =matched, matched\\{
			define matched
			ccall func
		\\}
	\}
	match =matched func=(fargs=), matched _argum\{
		match obj->proc, func\\{
			define matched
			mcall func, fargs
		\\}
		match =matched obj:proc, matched func\\{
			define matched
			mcall func, fargs
		\\}
		match =matched, matched\\{
			ccall func, fargs
		\\}
	\}
}