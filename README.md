# Automation-Script-using-Static-Analysis-For-PE

Automation-Script-using-Static-Analysis-For-PE is a Python application that automatically perform a static analysis over Portable Executables.

## Description

This application is designed to perform methods of static analysis automatically for Portable Executables and also create a risk assessment logic to clasify if the PE is malign or benign.

## Features

1. File header analysis
- PE file entropy.
- Check for common packers.
- Entropy for each section.
- Files w/o extension.
- Check for numbers of sections.
- Unusual ImageBase.
- Atypical SizeOfHeaders.
- Very small section alignment.
- ASLR (Address Space Layout Randomization).
- Entry point out outside defined sections.

## Requirements

1. At least Python 3.12.5 

2. MSVC v14.xx


## Installation

1. Clone the repository:

    ```shell
    git clone https://github.com/emichulo/Automation-Script-using-Static-Analysis-For-PE.git
    ```

2. Install the required dependencies:

    ```shell
    pip install -r requirements.txt
    ```

## Usage

1. 
- Set the path to your folder with the PE's.
- Name the text file for the analysis output.

2. Run the application:

    ```shell
    python src/main.py
    ```

