<!--
SPDX-FileCopyrightText: 2026 Nicolas Iooss

SPDX-License-Identifier: MIT
-->

# Solution for Synacktiv's 2025 Winter Challenge: Quinindrome

This repository contains a solution of a challenge organized by Synacktiv in December 2025: [2025 Winter Challenge: Quinindrome](https://www.synacktiv.com/en/publications/2025-winter-challenge-quinindrome).

There is a [write-up](./writeup.md), 3 solutions with different scores and some Python scripts used to craft these solutions.

The one with the lowest score (81) is:

```console
$ xxd solution_3_minimal.bin
00000000: 7f45 4c46 80cd 584b 80cd 51b2 4508 e1c1  .ELF..XK..Q.E...
00000010: 0200 0300 b904 0443 3900 0300 2c00 0000  .......C9...,...
00000020: 2c00 0000 0100 205e 5f5e 2000 0100 0000  ,..... ^_^ .....
00000030: 2c00 0000 2c00 0300 3943 0404 b900 0300  ,...,...9C......
00000040: 02c1 e108 45b2 51cd 804b 58cd 8046 4c45  ....E.Q..KX..FLE
00000050: 7f                                       .

$ ./test_script.sh solution_3_minimal.bin
[+] First check passed: binary is a byte-wise palindrome.
[+] Second check passed: binary is a true quine, its output matches itself.
[+] Both checks passed: your binary is a very nice quinindrome!
[+] Your score: 81
```

It enabled me to win first place :tada:
