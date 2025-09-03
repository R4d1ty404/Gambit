# Gambit

A high-performance, JS-aware Python crawler for discovering and classifying endpoints on a website.

This tool recursively crawls a target website, renders JavaScript, and identifies interesting links from various sources including `<a>` tags, comments, forms, and JS files.

## Features

-   Recursive crawling up to a specified depth
-   Handles JavaScript-rendered sites using Selenium
-   Advanced endpoint discovery (HTML comments, JS files, forms)
-   Intelligent link classification with regular expressions
-   High-performance multithreading
-   Generates interactive HTML reports and filtered text files

## Installation

1.  Clone the repository to your local machine:
    ```bash
    git clone [https://github.com/R4d1ty404/Gambit.git](https://github.com/R4d1ty404/Gambit.git)
    ```
2.  Navigate into the project directory:
    ```bash
    cd Gambit
    ```
3.  Install all the required Python packages using the `requirements.txt` file:
    ```bash
    pip install -r requirements.txt
    ```

## Usage Guide

Here is the basic command structure:

```bash
python3 gambit.py <URL> [OPTIONS]