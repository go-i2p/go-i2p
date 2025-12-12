LLM Usage Disclosure
====================

go-i2p allows cautious, disclosed use of LLM generated code under certain conditions.
This document attempts to provide transparency about that usage.

The enlightened position, in our opinion, is that LLMs cannot help you if you cannot think, and if you can think, then LLMs aren't really necessary.
However, what they are, fast word-predictors, can be useful for certain tasks(mostly by virtue of being fast).
Our advice is to use them for discovering issues in code which was written by a human.
Typically we do this by prompting the LLM to seek out issues in a small, focused section of the codebase, write a unit test demonstrating the issue, and generate a report about the issue.
We also asked the LLM to do package-level protocol compliance, code quality, and red-team reviews.
Then a human(idk, for instance) validates or invalidates the report and implements a fix.

It is important to remember that LLM's don't really "know" things, they "predict" things while speaking in an authoritative voice.
They are sometimes good at making accurate predictions, but they will *always* behave as if they are perfectly correct.
They are absolutely worse-than-useless to people who are uncritical of their output.
You need to treat it like the dumb co-worker who proposed to port your whole codebase to a new language 6 years ago. #oddlyspecific

LLMs have been used for:
------------------------

 - Test generation
 - Code review
 - Documentation suggestions
 - Refactoring suggestions

Code review type usage produced freestanding bug reports in markdown documents, which were then reviewed and resolved by a human.

Allowing the LLM to generate tests has led to significant test accumulation. While this has been a small problem as new features have broken old negative tests which relied on `unimplemented` error messages, ultimately these negative tests were turned into unit tests and this is no longer a problem.

LLM's have *not* been used for:
-------------------------------

 - Non-test code.
 - Handling any long-term secret material(there is none)
 - No code or documentation of any kind(test or library) has been checked in without a human reviewer

LLMs that have been used are:
-----------------------------

 - claude-3.5-sonnet
 - claude-4.0-sonnet
 - claude-4.5-sonnet

All LLM assistance has been provided by Github Copilot.
