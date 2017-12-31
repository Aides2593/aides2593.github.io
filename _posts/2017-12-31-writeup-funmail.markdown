---
layout: post
title:  "[TUCTF 2017][Funmail - RE25]"
date:   2017-12-31 16:31:39 +0700
categories: writeup re
---
# [TUCTF 2017][Funmail - RE25]

>One of our employees has locked himself out of his account. can you help 'john galt' recover his password? And no snooping around his emails you hear.
funmail - md5: 2462f28c6d64be1dc5658dc5f7bc06b9
[funmail](https://tuctf.asciioverflow.com/files/76a9e868d90b7229465aa972b49a8e4c/funmail)

OK. Kiểm tra sơ qua thông tin về file.
{% highlight bash %}
$file funmail
funmail: ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=99133c493a1b1bafb6873920626bc37d39ae85a9, not stripped
{% endhighlight %}
Không có gì đặc biệt. ```funmail``` thuộc kiểu ELF 32bit

Load thử vào ```ida32``` và kiểm tra hàm main

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s1; // [sp+0h] [bp-92h]@2
  char s; // [sp+40h] [bp-52h]@6
  char s2[4]; // [sp+80h] [bp-12h]@1
  int *v7; // [sp+8Eh] [bp-4h]@1

  v7 = &argc;
  strcpy(s2, "john galt");
  printWelcome();
  while ( 1 )
  {
    while ( 1 )
    {
      puts("\t--Please login--");
      printf("Username: ");
      if ( getLine(&s1, 64) )
      {
        puts("Input is too long");
        return 1;
      }
      if ( !strcmp(&s1, s2) )
        break;
      printf("*We have no users with the username: '%s'\n", &s1);
    }
    printf("Password: ");
    if ( getLine(&s, 64) )
    {
      puts("Input is too long");
      return 1;
    }
    if ( !strcmp(&s, password) )
      break;
    puts("*Incorrect password");
  }
  printf("\tWelcome %s!\n", &s1);
  return showEmails();
}
```
Thấy rằng strings ```s1(Username người dùng nhập)``` được so sánh với ```s2 - john galt```

Tiếp đó ```s(password người dùng nhập)``` được so sánh với ```password(biến)```

Trace biến ```password``` ta được

```c
.data:00003080 password        db 'this-password-is-a-secret-to-everyone!',0
```
Như vậy ta có được các thông tin

```Username:``` john galt

```Password: ```this-password-is-a-secret-to-everyone!

Thử run chương trình và nhập vào ta sẽ được flag của challenge này là:

```TUCTF{d0n7_h4rdc0d3_p455w0rd5}```

```Ngoài lề:```

Nếu tiếp tục trace theo hàm ```showEmails``` ta được

```c
signed int showEmails()
{
  char s1; // [sp+0h] [bp-48h]@1

  while ( 1 )
  {
    puts("You have 1 unread email.");
    puts("1) Read Email");
    puts("2) Quit");
    printf(">> ");
    if ( getLine(&s1, 64) )
    {
      puts("Input is too long");
      return 1;
    }
    if ( !strcmp(&s1, "1") )
    {
      printEmail();
      return 0;
    }
    if ( !strcmp(&s1, "2") )
      break;
    puts("Improper input!");
  }
  puts("Goodbye.");
  return 0;
}
```

Tiếp tục với hàm ```printEmail```
```c
int printEmail()
{
  puts("--------------------------------------");
  puts("From:\tLeeroy Jenkins");
  puts("To:\twhoisjohngalt");
  puts("Subject: RE: I need a flag");
  puts((const char *)&unk_11D5);
  puts("Hey John it's Leeroy.");
  puts("You were asking about a fun flag to use in your next challenge");
  puts("and I think I got one. Tell me what you think of:");
  printFlag();
  puts("Get back to me as soon as you can. Thanks!");
  return puts("--------------------------------------");
}
```

```printFlag:```
```c
int printFlag()
{
  char v1[30]; // [sp+Eh] [bp-5Ah]@5
  char v2; // [sp+2Ch] [bp-3Ch]@4
  char s[4]; // [sp+2Dh] [bp-3Bh]@1
  signed __int32 v4; // [sp+4Ch] [bp-1Ch]@5
  signed __int32 v5; // [sp+50h] [bp-18h]@1
  signed __int32 k; // [sp+54h] [bp-14h]@7
  signed __int32 j; // [sp+58h] [bp-10h]@4
  signed __int32 i; // [sp+5Ch] [bp-Ch]@1

  strcpy(s, "z2vb7m223dX4v7wvb3rX0f7v|T@WO@");
  v5 = strlen(s);
  for ( i = 0; i < v5; ++i )
  {
    s[i] ^= 7u;
    s[i] = rot13(s[i]);
  }
  v2 = 0;
  for ( j = 0; j < v5; ++j )
  {
    v4 = v5 - j - 1;
    v1[j] = s[v4];
  }
  for ( k = 0; k < v5; ++k )
    s[k] = v1[k];
  puts(s);
  return 0;
}
```
Như vậy ```Flag``` nằm ở hàm ```printFlag```

Với string ```"z2vb7m223dX4v7wvb3rX0f7v|T@WO@"``` thực hiện ```xor``` từng kí tự với ```7```, ```rot13``` rồi viết string theo thứ tự ngược lại ta sẽ được flag

python code:
```python
import string
rot13 = string.maketrans( 
    "ABCDEFGHIJKLMabcdefghijklmNOPQRSTUVWXYZnopqrstuvwxyz", 
    "NOPQRSTUVWXYZnopqrstuvwxyzABCDEFGHIJKLMabcdefghijklm")
s = "z2vb7m223dX4v7wvb3rX0f7v|T@WO@"

tmp = ""
for i in range(0, len(s)):
    tmp += chr(ord(s[i]) ^ 7)
tmp = string.translate(tmp, rot13)
print tmp[::-1]
```