# Blackfin processor support for Ghidra

## Status

### Disassembly
All Blackfin instructions should be disassmbled correctly.
Blackfin+ instructions are not implemented.

Blackfin assembly syntax differs from most other assembly syntaxes in that it does not use mnenomics, but uses rather a mathematical syntax.

    R0 = R1 + R2
    [--SP] = R1

As ghidra more or less requires mnemonics in the disassembly, mneomics are added but the syntax after that is close to the blackfin assembly syntax.

    ADD  R0 = R1 + R2
    PUSH [--SP] = R1

### P-code
Implementation for most of the general purpose instructions is done.
Most of the DSP instructions are not implemented.

From all the status flags only the CC flag is implemented.

Parallel execution of one 32bit instruction and two 16bit instructions is only marked with '||' at the mnenomic of the 32bit instruction but otherwise not handled.

Hardware loops are not handled.


## Installation
Use gradle to build extension: `GHIDRA_INSTALL_DIR=${GHIDRA_HOME} gradle` and use Ghidra to install it: `File → Install Extensions...`

## Links
* [Blackfin Processor Programming Reference (Rev. 2.2)](https://www.analog.com/media/en/dsp-documentation/processor-manuals/Blackfin_pgr_rev2.2.pdf)
* [Blackfin+ Processor Programming Reference (Rev. 1.0)](https://www.analog.com/media/en/dsp-documentation/processor-manuals/ADSP-BF70x_Blackfin_Programming_Reference.pdf)

