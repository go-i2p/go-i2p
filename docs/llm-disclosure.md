LLM Usage Disclosure
====================

go-i2p allows cautious, disclosed use of LLM generated code under certain conditions.
This document attempts to provide transparency about that usage.

The enlightened position, in our opinion, is that LLMs cannot help you if you cannot think, and if you can think, then LLMs aren't really necessary.
However, what they are, fast word-predictors, can be useful for certain tasks(mostly by virtue of being fast).
Our advice is to use them for discover issues in code which was written by a human.
Typically we do this by prompting the LLM to seek out issues in a small, focused section of the codebase, write a unit test demonstrating the issue, and generate a report about the issue.
Then a human(idk, for instance) validates the report and implements a fix.

LLMs have been used for:
------------------------

 - Test generation
 - Code review
 - Documentation suggestions
 - Refactoring suggestions

Code review type usage produced freestanding bug reports in markdown documents, which were then reviewed and resolved by a human.

LLM's have *not* been used for:
-------------------------------

 - Non-test code.
 - Handling any secret material(there is none)
 - No code or documentation of any kind(test or library) has been checked in without a human reviewer

LLMs that have been used are:
-----------------------------

 - claude-3.5-sonnet
 - claude-4.0-sonnet
 - claude-4.5-sonnet

All LLM assistance has been provided by Github Copilot.
