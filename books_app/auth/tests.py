import os
from unittest import TestCase

from datetime import date
 
from books_app.extensions import app, db, bcrypt
from books_app.models import Book, Author, User, Audience

"""
Run these tests with the command:
python -m unittest books_app.main.tests
"""

#################################################
# Setup
#################################################

def create_books():
    a1 = Author(name='Harper Lee')
    b1 = Book(
        title='To Kill a Mockingbird',
        publish_date=date(1960, 7, 11),
        author=a1
    )
    db.session.add(b1)

    a2 = Author(name='Sylvia Plath')
    b2 = Book(title='The Bell Jar', author=a2)
    db.session.add(b2)
    db.session.commit()

def create_user():
    password_hash = bcrypt.generate_password_hash('password').decode('utf-8')
    user = User(username='me1', password=password_hash)
    db.session.add(user)
    db.session.commit()

#################################################
# Tests
#################################################

class AuthTests(TestCase):
    """Tests for authentication (login & signup)."""
 
    def setUp(self):
        """Executed prior to each test."""
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        app.config['DEBUG'] = False
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        self.app = app.test_client()
        db.drop_all()
        db.create_all()
        # Ensure user is logged out before each test
        with self.app.session_transaction() as session:
            session.clear()
            session.pop('_user_id', None)
            session.pop('_fresh', None)
            session.pop('_id', None)

    def test_signup(self):
        """Test that a user can sign up."""
        # Make a POST request to /signup
        post_data = {
            'username': 'testuser',
            'password': 'testpassword'
        }
        self.app.post('/signup', data=post_data)

        # Check that the user now exists in the database
        user = User.query.filter_by(username='testuser').one()
        self.assertIsNotNone(user)
        self.assertEqual(user.username, 'testuser')

    def test_signup_existing_user(self):
        """Test that a user cannot sign up with an existing username."""
        # Create a user
        create_user()

        # Make a POST request to /signup with the same username & password
        post_data = {
            'username': 'me1',
            'password': 'password'
        }
        response = self.app.post('/signup', data=post_data)

        # Check that the form is displayed again with an error message
        response_text = response.get_data(as_text=True)
        self.assertIn('That username is taken', response_text)

    def test_login_correct_password(self):
        """Test that a user can log in with correct credentials."""
        # Create a user
        create_user()

        # Make a POST request to /login
        post_data = {
            'username': 'me1',
            'password': 'password'
        }
        self.app.post('/login', data=post_data)

        # Check that the "login" button is not displayed on the homepage
        response = self.app.get('/', follow_redirects=True)
        response_text = response.get_data(as_text=True)
        self.assertNotIn('Log In', response_text)

    def test_login_nonexistent_user(self):
        """Test that login fails for non-existent user."""
        # Make a POST request to /login
        post_data = {
            'username': 'nonexistent',
            'password': 'password'
        }
        response = self.app.post('/login', data=post_data)

        # Check that the login form is displayed again with an error message
        response_text = response.get_data(as_text=True)
        self.assertIn('No user with that username', response_text)

    def test_login_incorrect_password(self):
        """Test that login fails with incorrect password."""
        # Create a user
        create_user()

        # Make a POST request to /login with incorrect password
        post_data = {
            'username': 'me1',
            'password': 'wrongpassword'
        }
        response = self.app.post('/login', data=post_data)

        # Check that the login form is displayed again with an error message
        response_text = response.get_data(as_text=True)
        self.assertIn("Password doesn't match. Please try again.", response_text)

    def test_logout(self):
        """Test that a user can log out."""
        # Create a user
        create_user()

        # Log the user in
        post_data = {
            'username': 'me1',
            'password': 'password'
        }
        self.app.post('/login', data=post_data)

        # Make a GET request to /logout
        self.app.get('/logout')

        # Check that the "login" button appears on the homepage
        response = self.app.get('/', follow_redirects=True)
        response_text = response.get_data(as_text=True)
        self.assertIn('Log In', response_text)
