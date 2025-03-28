from flask_wtf import FlaskForm
from wtforms import PasswordField, StringField, SelectField, SubmitField
from wtforms.validators import DataRequired

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class MemberForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    status = StringField('Status', validators=[DataRequired()])
    submit = SubmitField('Submit')

class ClassForm(FlaskForm):
    class_name = StringField('Class Name', validators=[DataRequired()])
    class_time = StringField('Schedule', validators=[DataRequired()])
    instructor = StringField('Instructor', validators=[DataRequired()]) 
    submit = SubmitField('Add Class')

class RegisterClassForm(FlaskForm):
    class_id = SelectField('Select Class', coerce=int)
    submit = SubmitField('Register')
