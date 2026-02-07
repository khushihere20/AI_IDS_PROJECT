# pytest cache directory #

This directory contains data from the pytest's cache plugin,
which provides the `--lf` and `--ff` options, as well as the `cache` fixture.

**Do not** commit this to version control.

See [the docs](https://docs.pytest.org/en/stable/how-to/cache.html) for more information.

# AI-based Intrusion Detection System

## Overview
This project is an AI-powered Intrusion Detection System (IDS) built using Machine Learning and Flask.
It detects network attacks using the NSL-KDD dataset.

## Features
- ML-based attack detection
- Flask web interface
- User authentication
- CSV file upload
- Attack classification

## Tech Stack
- Python
- Flask
- Scikit-learn
- HTML/CSS

## Project Structure
- training/ → model training scripts
- detection/ → attack detection logic
- webapp/ → Flask web app
- data/ → dataset

## How to Run
1. Clone the repository
2. Install dependencies:
   pip install -r requirements.txt
3. Train the model:
   python training/train_model.py
4. Run the app:
   python app.py
