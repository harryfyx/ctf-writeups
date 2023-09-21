## Description

- category: rev
- link: https://score.quals.seccon.jp/challenges/23
- difficulty: 106 pt (easy?)

```
Pickle infected with COVID-19
```

## Solve

Disclaimer: I didn't solve last part of this challenge, since I don't know crypto.

We see a python script. Running the script, it asks for a flag, and checks for it.

With some search online, we know that pickle is insecure, that it allows code execution in pickle. Basically, pickle `load` acts as a virtual machine, and executes pickle bytecode.

We can disassemble the pickle bytecode with `pickletools`.

```Py
>>> payload = b'\x8c\x08builtins\x8c\x07getattr\x93\x942\x8c\x08builtins\x8c\x05input\x93\x8c\x06FLAG> \x85R\x8c\x06encode\x86R)R\x940g0\n\x8c\x08builtins\x8c\x04dict\x93\x8c\x03get\x86R\x8c\x08builtins\x8c\x07globals\x93)R\x8c\x01f\x86R\x8c\x04seek\x86R\x94g0\n\x8c\x08builtins\x8c\x03int\x93\x8c\x07__add__\x86R\x940g0\n\x8c\x08builtins\x8c\x03int\x93\x8c\x07__mul__\x86R\x940g0\n\x8c\x08builtins\x8c\x03int\x93\x8c\x06__eq__\x86R\x940g3\ng5\n\x8c\x08builtins\x8c\x03len\x93g1\n\x85RM@\x00\x86RM\x05\x01\x86R\x85R.0g0\ng1\n\x8c\x0b__getitem__\x86R\x940M\x00\x00\x940g2\ng3\ng0\ng6\ng7\n\x85R\x8c\x06__le__\x86RM\x7f\x00\x85RMJ\x01\x86R\x85R.0g2\ng3\ng4\ng5\ng3\ng7\nM\x01\x00\x86Rp7\nM@\x00\x86RMU\x00\x86RM"\x01\x86R\x85R0g0\ng0\n]\x94\x8c\x06append\x86R\x940g8\n\x8c\x0b__getitem__\x86R\x940g0\n\x8c\x08builtins\x8c\x03int\x93\x8c\nfrom_bytes\x86R\x940M\x00\x00p7\n0g9\ng11\ng6\n\x8c\x08builtins\x8c\x05slice\x93g4\ng7\nM\x08\x00\x86Rg4\ng3\ng7\nM\x01\x00\x86RM\x08\x00\x86R\x86R\x85R\x8c\x06little\x86R\x85R0g2\ng3\ng4\ng5\ng3\ng7\nM\x01\x00\x86Rp7\nM\x08\x00\x86RMw\x00\x86RM\xc9\x01\x86R\x85R0g0\n]\x94\x8c\x06append\x86R\x940g0\ng12\n\x8c\x0b__getitem__\x86R\x940g0\n\x8c\x08builtins\x8c\x03int\x93\x8c\x07__xor__\x86R\x940I1244422970072434993\n\x940M\x00\x00p7\n0g13\n\x8c\x08builtins\x8c\x03pow\x93g15\ng10\ng7\n\x85Rg16\n\x86RI65537\nI18446744073709551557\n\x87R\x85R0g14\ng7\n\x85Rp16\n0g2\ng3\ng4\ng5\ng3\ng7\nM\x01\x00\x86Rp7\nM\x08\x00\x86RM\x83\x00\x86RM\xa7\x02\x86R\x85R0g0\ng12\n\x8c\x06__eq__\x86R(I8215359690687096682\nI1862662588367509514\nI8350772864914849965\nI11616510986494699232\nI3711648467207374797\nI9722127090168848805\nI16780197523811627561\nI18138828537077112905\nl\x85R.'
>>> import pickletools
>>> pickletools.dis(payload)
0: \x8c SHORT_BINUNICODE 'builtins'
10: \x8c SHORT_BINUNICODE 'getattr'
19: \x93 STACK_GLOBAL
20: \x94 MEMOIZE    (as 0)
21: 2    DUP
22: \x8c SHORT_BINUNICODE 'builtins'
32: \x8c SHORT_BINUNICODE 'input'
39: \x93 STACK_GLOBAL
40: \x8c SHORT_BINUNICODE 'FLAG> '
48: \x85 TUPLE1
49: R    REDUCE
50: \x8c SHORT_BINUNICODE 'encode'
58: \x86 TUPLE2
59: R    REDUCE
60: )    EMPTY_TUPLE
61: R    REDUCE
62: \x94 MEMOIZE    (as 1)
63: 0    POP
64: g    GET        0
67: \x8c SHORT_BINUNICODE 'builtins'
77: \x8c SHORT_BINUNICODE 'dict'
83: \x93 STACK_GLOBAL
84: \x8c SHORT_BINUNICODE 'get'
89: \x86 TUPLE2
90: R    REDUCE
91: \x8c SHORT_BINUNICODE 'builtins'
101: \x8c SHORT_BINUNICODE 'globals'
110: \x93 STACK_GLOBAL
111: )    EMPTY_TUPLE
112: R    REDUCE
113: \x8c SHORT_BINUNICODE 'f'
116: \x86 TUPLE2
117: R    REDUCE
118: \x8c SHORT_BINUNICODE 'seek'
124: \x86 TUPLE2
125: R    REDUCE
126: \x94 MEMOIZE    (as 2)
127: g    GET        0
130: \x8c SHORT_BINUNICODE 'builtins'
140: \x8c SHORT_BINUNICODE 'int'
145: \x93 STACK_GLOBAL
146: \x8c SHORT_BINUNICODE '__add__'
155: \x86 TUPLE2
156: R    REDUCE
157: \x94 MEMOIZE    (as 3)
158: 0    POP
159: g    GET        0
162: \x8c SHORT_BINUNICODE 'builtins'
172: \x8c SHORT_BINUNICODE 'int'
177: \x93 STACK_GLOBAL
178: \x8c SHORT_BINUNICODE '__mul__'
187: \x86 TUPLE2
188: R    REDUCE
189: \x94 MEMOIZE    (as 4)
190: 0    POP
191: g    GET        0
194: \x8c SHORT_BINUNICODE 'builtins'
204: \x8c SHORT_BINUNICODE 'int'
209: \x93 STACK_GLOBAL
210: \x8c SHORT_BINUNICODE '__eq__'
218: \x86 TUPLE2
219: R    REDUCE
220: \x94 MEMOIZE    (as 5)
221: 0    POP
222: g    GET        3
225: g    GET        5
228: \x8c SHORT_BINUNICODE 'builtins'
238: \x8c SHORT_BINUNICODE 'len'
243: \x93 STACK_GLOBAL
244: g    GET        1
247: \x85 TUPLE1
248: R    REDUCE
249: M    BININT2    64
252: \x86 TUPLE2
253: R    REDUCE
254: M    BININT2    261
257: \x86 TUPLE2
258: R    REDUCE
259: \x85 TUPLE1
260: R    REDUCE
261: .    STOP                                                                                                        highest protocol among opcodes = 4    
>>> len(payload)
1004 
```

First, there is one thing weird, that this disassembly stops at 261, while the length of the payload is 1004. Something is missing. If we tinker with it a little bit, we can see that this disassembler sees a `STOP` command and stops disassembling. We can assume that there is more stuff after that.

What is cool about pickle virtual machine is that, if we check the python pickle library, we can see the nicely written source code. Additionally, we can change that library source code and add breakpoints and prints to it.

```Py
# pickle source code
...
class _Unpickler:
    ...

    def load(self):
        """Read a pickled object representation from the open file.

        Return the reconstituted object hierarchy specified in the file.
        """
        # Check whether Unpickler was initialized correctly. This is
        # only needed to mimic the behavior of _pickle.Unpickler.dump().
        if not hasattr(self, "_file_read"):
            raise UnpicklingError("Unpickler.__init__() was not called by "
                                  "%s.__init__()" % (self.__class__.__name__,))
        self._unframer = _Unframer(self._file_read, self._file_readline)
        self.read = self._unframer.read
        self.readinto = self._unframer.readinto
        self.readline = self._unframer.readline
        self.metastack = []
        self.stack = []
        self.append = self.stack.append
        self.proto = 0
        read = self.read
        dispatch = self.dispatch
        globals()['f'] = self.fyxfile
        try:
            while True:
                ######### OUR DEBUG STUFF #########
                print(self.stack)
                print(self.memo)
                print()
                key = read(1)
                if key == b'.': breakpoint()
                ######### OUR DEBUG STUFF #########
                if not key:
                    raise EOFError
                assert isinstance(key, bytes_types)
                dispatch[key[0]](self)
        except _Stop as stopinst:
            return stopinst.value

...

# Use the faster _pickle if possible
try:
    ######### OUR DEBUG STUFF #########
    # we want this to use python for simplicity
    raise ImportError(); 
    ######### OUR DEBUG STUFF #########
    from _pickle import (
        PickleError,
        PicklingError,
        UnpicklingError,
        Pickler,
        Unpickler,
        dump,
        dumps,
        load,
        loads
    )
except ImportError:
    Pickler, Unpickler = _Pickler, _Unpickler
    dump, dumps, load, loads = _dump, _dumps, _load, _loads

...
```

So here is a simple explanation of pickle virtual machine. It has a stack (list), and a memo (dict). For example, the stack can have `[<__getattr__ function>, 'aaaaa', '__eq__']`, and memo can have `{0: 1337, 1: <int __mul__>}`. Basically, they store python objects. When it see a reduce command, it runs stuff together, so `[<__getattr__ function>, 'aaaaa', '__eq__']` becomes the actual method returned by `getattr('aaaaa', '__eq__')`, which is a object like `<method-wrapper '__eq__' of str object at 0x7fda37f45030>`.

Now we have a pickle debugger, and then it is easy to see how everything works.

One other important thing is that the pickle bytecode tries to find the `BytesIO` object, which is the payload object. The bytecode seeks functions so that it can jump to places. This explains why the disassembled text only has position 261, because it will manually seek to position 262 and skip the stop command.

Now, keep tinkering, and we see some comparing on the stack such as this one `[<method-wrapper '__eq__' of list object at 0x7f9e098c27c0>, ([8215359690687096682, 1862662588367509514, 8350772864914849965, 11616510986494699232, 3711648467207374797, 9722127090168848805, 16780197523811627561, 18138828537077112905],)]`. So now we know the correct values. 

We can check how each part of our list object is generated by looking at the logs. Then, with some crypto knowledge, we can have this script. Provided by my friend Matty.

```Py
from Crypto.Util.number import *

correct = [8215359690687096682, 1862662588367509514, 8350772864914849965, 11616510986494699232, 3711648467207374797, 9722127090168848805, 16780197523811627561, 18138828537077112905]

for i in range(8):
    xor_value = 1244422970072434993 if i == 0 else correct[i - 1]
    c = correct[i]
    e = 65537
    n = 18446744073709551557
    phi = n - 1
    d = inverse(e, phi)
    print((pow(c, d, n) ^ xor_value).to_bytes(8, 'little').decode(), end='')
```

Flag is: SECCON{Can_someone_please_make_a_debugger_for_Pickle_bytecode??}

Well, what is funny is that, I actually have a "pickle bytecode debugger", but didn't solve the crypto.