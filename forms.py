from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, FileField
from wtforms.validators import Regexp
from wtforms.fields import EmailField
from wtforms.validators import DataRequired, Length, EqualTo

class RegistrationForm(FlaskForm):
    userid = StringField('Cognizant UserID', validators=[DataRequired(), Length(min=3, max=64), Regexp('^[0-9]+$', message='UserID must be numbers only.')])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class ClipboardForm(FlaskForm):
    content = TextAreaField('Clipboard', validators=[DataRequired()])
    submit = SubmitField('Save')


# Form for file upload in fileshare
class FileShareForm(FlaskForm):
    file = FileField('Upload File', validators=[DataRequired()])
    submit = SubmitField('Upload')
