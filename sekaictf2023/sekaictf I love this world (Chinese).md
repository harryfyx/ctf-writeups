## 描述

- 分类: misc
- 链接: https://ctf.sekai.team/challenges#I-love-this-world-4
- 难度: 1 star (Beginner)

```
Vocaloid is a great software to get your computer sing the flag out to you, but 
what if you can’t afford it? No worries, there are plenty of other free tools 
you can use. How about — let’s say — this one?

Flag format (Regex): SEKAI\{[A-Z0-9]+\}.

Author: pamLELcu

❖ Note
No romanization or Japanese translation is needed to solve the challenge. The flag you find will satisfy the flag regex. The flag in Japanese is a fake flag.
```

翻译：Vocaloid可以把flag唱给你听，但是又太贵。还好有很多免费的软件也可以，比如这个？注：答案不需要翻译日语。

我们在题目中得到一个svp文件，然后需要从中拿到flag。

## 解决

搜索svp文件格式，我找到这个网站。

https://fileinfo.com/extension/svp

所以我下载了Sythesizer V。

打开这个文件后，我们看到了音符，上面有歌词写着`SEKAI{blah blah blah}`只不过里面是日文，这不是flag。

根据题目中描述，软件会把flag唱出来。如果我们点播放按钮，能听到一个BGM但是没有人声。

在又尝试了一些按钮之后，我发现安装不同的voice database就能听到唱歌（安装方式https://forum.synthesizerv.com/t/topic/3026）。我尝试的是日语的voice database。那么现在试一个英文的。

可以下载这个，是英文的，而且免费。

https://resource.dreamtonics.com/download/English/Voice%20Databases/Lite%20Voice%20Databases/Eleanor%20Forte/

现在播放，能听到`flag blah blah blah`，一个一个字母唱了出来。每个note为一个字符。

这不太能听懂，我们可以把这道题简化。用AI识别出来歌词是不行的，因为如果哪怕一个字母错了，你都不知道是哪一个。

首先我们解析这个svp文件（你可以用 https://jsonformatter.org/），然后找到phonemes。在识别出来这个note对应的字符后，可以在文件中替换所有的匹配项。

举个例子

```json
...

"notes": [
    {
        "onset": 2660700000,
        "duration": 235200000,
        "lyrics": "き",
        "phonemes": "eh f",
        "pitch": 68,
        "detune": 0,
        "attributes": {
        "tF0Offset": 0,
        "tF0Left": 0.06666667014360428,
        "tF0Right": 0.06666667014360428,
        "dF0Left": 0,
        "dF0Right": 0,
        "dF0Vbr": 0
        }
    },
    {
        "onset": 2895900000,
        "duration": 235200000,
        "lyrics": "み",
        "phonemes": "eh l",
        "pitch": 70,
        "detune": 0,
        "attributes": {
        "tF0Offset": 0,
        "tF0Left": 0.06666667014360428,
        "tF0Right": 0.06666667014360428,
        "dF0Left": 0,
        "dF0Right": 0,
        "dF0Vbr": 0
    }
    ...
```

这里我们确定第一个note听起来像F，所以就把所有的`eh f`都替换成`F`。

提示：右键点击note，然后disband the group。之后，如果觉得一个note太短或者音调太怪，你可以拖拽它以修改音调和长短。

有些note难以识别。我就把Z听错成了C。由于flag会生成一个句子，我们也可以以此作为提示。

最终，我们得到：`FLAG:SEKAI{SOME1ZFARAWAYTMR15SEQUELTOOURDREAMTDY}`