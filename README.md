# Excalibur2

## Description

A simple integrated library for CTFers specializing in PWN challenges.

This Python library includes common functions used in PWN challenges, aiming to simplify the process of exp for PWN challenges, helping pwners save time and improve efficiency in solving problems.

We warmly welcome all masters to use Excalibur, and we also welcome feedback and guidance on our code.

## Install

Install Excalibur2 by 

> pip3 install Excalibur2

check for updates

>  python3 -m Excalibur2.\_\_update\_\_

update package

> pip3 install Excalibur2 --upgrade

## Help

python built-in help

> check help documention
>
> `import Excalibur2`
>
> `help(Excalibur2)`
>
> check help for func
>
> `from Excalibur2 import *`
>
> `help(function)`

more details Please visit https://lmarch2.top/posts/8c945bd4/ 

## Release

### 2.4，Feb 8, 2024

Renamed `contextset` to `setcontext`.
Added a new function `prhl`.
Set the default parameter for `proc` to `./pwn`.
Added automatic address calculation for base addresses.
Fixed bugs in the `csu` and `ropgadget` functions.
Modified some aliases.

### 2.2,  Feb 8, 2024

Fix some bugs due to uncorrect package name

### 2.1,  Feb 8, 2024

Support custom debugging terminal and add check update function

### 2.0,  Feb 8, 2024

The birthday of the package

