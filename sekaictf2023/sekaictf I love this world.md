## Description

- category: misc
- link: https://ctf.sekai.team/challenges#I-love-this-world-4
- difficulty: 1 star (Beginner)

```
Vocaloid is a great software to get your computer sing the flag out to you, but 
what if you can’t afford it? No worries, there are plenty of other free tools 
you can use. How about — let’s say — this one?

Flag format (Regex): SEKAI\{[A-Z0-9]+\}.

Author: pamLELcu

❖ Note
No romanization or Japanese translation is needed to solve the challenge. The flag you find will satisfy the flag regex. The flag in Japanese is a fake flag.
```

We are given a svp file, and need to somehow find the flag inside it.

## Solve

Searching for the svp format, I found this website to be helpful.

https://fileinfo.com/extension/svp

So I downloaded Sythesizer V.

After opening the svp file with it, we see music notes, and some lyrics on it that says `SEKAI{blah blah blah}`, except that the flag is Japanese, which is fake.

As the problem description says, the software should sing the flag out to you. If we just hit the play button, there is a BGM but no human sounds with the default voice database.

After pushing some buttons, and downloading a random voice database (to change voice database https://forum.synthesizerv.com/t/topic/3026), I find that it now sings differently. Except that I was trying a Japanese database. So let's try a English one.

So we download this one. It is English, and free.

https://resource.dreamtonics.com/download/English/Voice%20Databases/Lite%20Voice%20Databases/Eleanor%20Forte/

Now we hit play, and hear it sings `flag blah blah blah` letter by letter. Each note is a character.

This is kind of hard to make out, so let's make it easier. Use AI to transcribe it won't work well, since if even one letter is wrong, you cannot debug it.

First we can parse the svp file (you can use https://jsonformatter.org/), and find the phonemes. After making out what letter (or digit and punctuation) does the phonemes correlate to, we replace all occurrences of the phonemes.

For example

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

Here we make sure that the first note sounds like an 'F', so replace all `eh f` with `F`.

Hint: Right click the notes, and disband the group. After that, if a note is too short or too pitchy, you can drag it to a different pitch and make the sound longer.

There are sounds that are hard to make out of. I mistook a 'Z' as 'C'. Since the flag will make up a sentence, we use it as a hint.

Finally, the notes are: `FLAG:SEKAI{SOME1ZFARAWAYTMR15SEQUELTOOURDREAMTDY}`