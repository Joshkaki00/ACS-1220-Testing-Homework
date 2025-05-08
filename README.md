# Books App Part 4 (Tests)

## Prerequisites

In order for this project's dependencies to install, you'll need PostgreSQL running on your computer.

Install it by opening your terminal, and pasting the following command:

```bash
brew install postgresql
```

## Setup

Clone this repository to your computer. 

**Take a look at the code** - it looks a bit different than what you're used to. Namely, the code is now separated out into several files rather than being written in a single `app.py` file. Since we're now writing model and form code as well as route code, this will help us to maintain some structure and separation.

**To run the code**, navigate to the project folder and run the following to create a virtual environment and install the required packages:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Then, copy the `.env.example` file to `.env`:

```bash
cp .env.example .env
```

Then you can run the following to run the Flask server:

```bash
python app.py
```

## Running the Tests

**To run all of the tests**, you can run the following from the root project directory:

```bash
python -m unittest discover
```

(Make sure you have unittest installed.)

**To run all tests from a single file**, run the following:

```bash
python -m unittest books_app.main.tests
```

**To run one specific test**, you can run the following:

```bash
python -m unittest books_app.main.tests.MainTests.test_homepage_logged_in
```

## Instructions

Navigate to `books_app/main/tests.py` and `books_app/auth/tests.py`, and complete the TODOs to finish all tests. Make sure you run the tests as you go along to ensure that they still pass!

## Resources

If you'd like more resources on working with Flask-WTForms, check out the following:

- [Unit Testing a Flask Application](https://www.patricksoftwareblog.com/unit-testing-a-flask-application/)
- [Testing Flask Applications](https://flask.palletsprojects.com/en/1.1.x/testing/)
- [Python Tutorial: Unit Testing Your Code with the unittest Module [VIDEO]](https://www.youtube.com/watch?v=6tNS--WetLI)
