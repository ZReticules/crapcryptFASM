include 'macro\struct.inc'
include 'macro\proc64.inc'
;обращаю внимание на вложенность. Чем больше уровень вложенности макроконструкций, тем больше нужно косых черт
;это определяет, на каком уровне вложенности обработается конкретное действие, выражение или переменная
macro make@table name, parent{								;создаем макросы, которые позволят нам определять и
															;переопределять методы
	struc method val\{
		\local matched
		match name, struct@lastname\\{						;в этой константе хранится имя последней обьявленной структуры
			name\\#@MStack equ . 							;загружаем на вершину константы-стека новый метод
			match _val:type, val\\\{						;для виртуальных методов(и возможно дальнейшего расширения)
				.Value equ _val								;сразу закрепляем за ним значение(обработчик)
				.Type equ type								;и тип - пока что только виртуальные
				define matched
			\\\}
			match =matched, matched\\\{						;если тип не указан явно
				.Value equ val								;значит статический
				.Type equ static
			\\\}
			match =this, .Value\\\{							;если значение обработчика - this, то это значит
				.Value equ name\\\#\\\.\\\#.				;что надо подставить имя метода в формате StructName.MethodName
			\\\}											;это работает, так как процедура это метка и доступна везде
		\\}	
	\}

	struc override NewVal{									;переопределеие метода
		match name, struct@lastname\\{
			match parentname, name\#@SParent\\\{			;раз метод переопределяется, значит он был у родителя
				irpv MethName, parentname\\\#@MStack\\\\{	;перебираем стековую переменную по значению с самого первого
				\\\\local matched							;подробнее irpv описан в документации
					if MethName eq .						;находим метод, имя которого совпадает с переопределяемым
						match =this, NewVal\\\\\{			;меняем ему значение. В случае, если это this
							.Value equ name\\#\\.\\#.		;выполняем описанную ранее операцию
							define matched
						\\\\\}
						match =matched, matched\\\\\{
							.Value equ NewVal				;иначе просто устанавливаем новое значение
						\\\\\}
					end if									;в будущем планирую сделать переопределение типа метода
				\\\\}
			\\\}
		\\}
	\}
}

macro def@struct{											;так как структуры имеют стековую природу и их старое значение
															;можно восстанавливать с помощью restruc, я использовал это
															;чтобы возвращать старое определение struct когда нужно
															;а потом снова генерировать новое определение макросом
	macro struct NameParent, DefTable\{
		\local matched@endt, matched@params					;тут происходит определение разных локалок для двух отдельных
															;матчеых if...else
		match name=[parent=], NameParent\\{
			define matched@params
			oldstruct@action equ name parent				;так как я активно использую старый struct, для него я сохраняю
															;значения, которые ему передам для генерации основной структуры
			struct@lastname equ name						;в этой переменной между struct и ends сохраняется 
															;имя последней использованной структуры
			name\\#@SParent equ parent						;к имени так же привязывается родитель
		\\}
		match =matched@params, matched@params\\{
			oldstruct@action equ NameParent					;если родителя нет, параметры устанавливаются таким образом
			struct@lastname equ NameParent
		\\}
		match DefTable, table\\{							;проверяем, установлено ли ключевое слово table
			define matched@endt
		\\}
		match =matched@endt, matched@endt\\{				;если нет, то мы сразу используем старое определение структуры
															;восстанавливать нам его не надо, так как внутри структуры
															;с таким же именем используется старое определение
															;это разработчиком компилятора сделано намеренно, дабы избежать рекурсии
			struct oldstruct@action
			restore oldstruct@action						;очищаем значение последнего действия для старого определения структуры
			match name, struct@lastname\\\{					;так как далее вызывается макрос make@table, а endt для него
															;не вызывается, мы устанавлиаем переменную, которая позволяет нам определить,
															;что нужно в ends подчистить за ним
				name\\\#@Purged equ "FALSE"
			\\\}
		\\}
		make@table struct@lastname
	\}
}

macro MStruct@GenMethods name, StackName{					;макрос для генерации методов
	irpv MethName, StackName\{								;перебираем стек методов
	local matched
		match =static, MethName\#.Type\\{					;если метод статический - устаналвиаем числовую переменную
			.\\#MethName = MethName\\#.Value				;в значение адреса обработчика
			define matched
		\\}
		match =matched, matched\\{
			.\\#MethName dq MethName\\#.Value				;если метод не статический, значит виртуальный
			restore name#@Virtual							;заодно здесь мы проверяем, нужно ли создавать для обьектов
			name#@Virtual equ "TRUE"						;поле с указателем на таблицу виртуальных методов
		\\}
		restore matched
	\}
}

macro endt{													;если в определении структуры использовалось ключевое слово table
															;то в конце перечисления методов необходимо вызвать endt
	restruc method											;он уничтожает определения макросов method и override
	restruc override
	match name, struct@lastname\{							;получаем старое имя структуры
		local matched
		name\#.Table:										;создаем метку-таблицу
		name\#@Virtual equ "FALSE"							;по умолчанию считаем, что таблица виртуальных методов не нужна
		match parentname, name\#@SParent\\{					;при генерации своих методов или методов предка мы и определим
															;так ли это
			MStruct@GenMethods parentname, parentname\\#@MStack
		\\}
		MStruct@GenMethods name, name\#@MStack
		purge struct										;вот здесь нам пригождается старое определение структуры
		struct oldstruct@action	
		restore oldstruct@action
		def@struct											;и восстанавливаем значение
	\}
}

macro ends{
	match name, struct@lastname\{
		local matched
		match ="FALSE", name\#@Purged\\{					;если table не использовался
			restruc method									;выполняем некоторые действия endt
			restruc methodoverride
			match name, struct@lastname\\\{
				name\\\#.Table:
				name\\\#@Virtual equ "FALSE"
				match parentname, name\#@SParent\\\\{
					MStruct@GenMethods parentname, parentname\\\\\#@MStack
				\\\\}
				restore oldstruct@action
			\\\}
		\\}
		purge struct
		ends
		def@struct				
		;здесь происходит переопределение стандартных
		;создаваемых struct макросов
		match ="TRUE", name\#@Virtual\\{					;если нужно создать указатель на таблице виртуальных методов
			define matched
			struc name [args]\\\{
				\\\common
				.VTable dq name\#.Table						;создаем на 8 байт раньше стандартного определения
				. name args
				.Table equ name\#.Table						;так же прикрепляем таблицу к обьекту статически
			\\\}
			macro name [args]\\\{							;если имени у обьекта нет, то просто создаем таблицу со значением
				\\\common
				dq name\#.Table
				name args
			\\\}
		\\}
		match =matched, matched\\{							;если не требуется
			struc name [args]\\\{
				\\\common
				restore .Table
				.Table equ name\\#.Table					;то просто прикрепляем таблицу статически
				name args
			\\\}
			macro name [args]\\\{							;если имени у обьекта нет, то стандартный обработчик
				\\\common
				name args
			\\\}
		\\}
		restore struct@lastname
	\}
}

macro @call ObjMethArgs&{
	common
	local matched
	match ObjMeth=(args=), ObjMethArgs\{					;если в скобках есть аргументы
		match [Obj->Meth], ObjMeth\\{						;проверка на вызов виртуального метода обьекта
			define matched
			mov r10, [Obj\\#.VTable]						;вызов через r10
			match Table, Obj\\#.Table\\\{
					;тут мы к смещению обьекта прибавляем смещение таблицы
					;вместе с методом, а потом вычитаем смещение таблицы
					;таким образом, если методы располагаются на одинаковом смещении
					;и имеют одинаковые имена
					;то для структур-наследников может вызываться их собственный метод
					;вместо метода предка
					ccall qword[r10+Table\\\#.\\\#Meth-Table], addr Obj, args
			\\\}
		\\}
		match =matched Obj->Meth, matched ObjMeth\\{		;для вызова статического метода обьекта
			define matched
			match Table, Obj\\#.Table\\\{
				ccall Table\\\#.\\\#Meth, addr Obj, args
			\\\}
		\\}
		match [Struct:Meth], ObjMeth\\{						;для вызова виртуального метода по таблице структуры
															;с помощью этого можно передавать обьект в методы предков
			define matched
			ccall qword[Struct\\#.Table\\#.\\#Meth], args
		\\}
		match =matched Struct:Meth, matched ObjMeth\\{		;для вызова статического метода по таблице
			define matched
			ccall Struct\\#.Table\\#.\\#Meth, args
		\\}
		match =matched, matched\\{							;иначе просто вызываем обычную процедуру
			ccall ObjMeth, args
		\\}
	\}
	match ObjMeth=(=), ObjMethArgs\{						;аналогично для вызова без аргументов
		match [Obj->Meth], ObjMeth\\{
			define matched
			mov r10, [Obj\\#.VTable]
			match Table, Obj\\#.Table\\\{
				ccall qword[r10+Table\\\#.\\\#Meth-Table], addr Obj
			\\\}
		\\}
		match =matched Obj->Meth, matched ObjMeth\\{
			define matched
			match Table, Obj\\#.Table\\\{
				ccall Table\\\#.\\\#Meth, addr Obj
			\\\}
		\\}
		match [Struct:Meth], ObjMeth\\{
			define matched
			ccall qword[Struct\\#.Table\\#.\\#Meth]
		\\}
		match =matched Struct:Meth, matched ObjMeth\\{
			define matched
			ccall Struct\\#.Table\\#.\\#Meth
		\\}
		match =matched, matched\\{
			ccall ObjMeth
		\\}
	\}
}
;вызываем новое определение для структуры
def@struct