import datetime
from functools import wraps
from flask import Flask, abort, request, redirect, render_template, session, url_for
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Table, Column, Integer, ForeignKey
from sqlalchemy import not_
from sqlalchemy.orm import relationship
from werkzeug.security import generate_password_hash, check_password_hash
import smtplib
from email.mime.text import MIMEText
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SelectField, SelectMultipleField, SubmitField, validators, BooleanField
from wtforms.validators import DataRequired
from wtforms.fields import SelectMultipleField
from wtforms.widgets import ListWidget, CheckboxInput
from werkzeug.datastructures import MultiDict
from sqlalchemy import case, desc
from flask_migrate import Migrate
from flask_login import login_required
from flask_login import LoginManager, UserMixin, login_user
from flask_oauthlib.client import OAuth
import requests



app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)

oauth = OAuth(app)

github = oauth.remote_app(
    'github',
    consumer_key='d8700b9c77591807f99f',
    consumer_secret='a37f3fab06b0dd023f8802f7d79760ec6d1d39f6',
    request_token_params={'scope': 'user:email'},
    base_url='https://api.github.com/',
    request_token_url=None,
    access_token_url='https://github.com/login/oauth/access_token',
    authorize_url='https://github.com/login/oauth/authorize'
)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    github_access_token = db.Column(db.String(250), unique=True)

    created_projects = db.relationship("Project", back_populates="admin")
    projects = db.relationship("ProjectMember", back_populates="user")
    issues = db.relationship('Issue', back_populates='created_by', foreign_keys='Issue.created_by_id')
    assigned_issues = db.relationship("IssueAssignment", back_populates="user")
    comments = db.relationship('Comment', back_populates = 'created_by', foreign_keys = 'Comment.created_by_id')


class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(200), nullable=False)
    admin_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    admin = db.relationship("User", back_populates="created_projects", uselist=False)
    issues = db.relationship('Issue', back_populates='project')
    members = db.relationship("ProjectMember", back_populates="project")

class ProjectMember(db.Model):
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)

    project = db.relationship("Project", back_populates="members")
    user = db.relationship("User", back_populates="projects")

class Issue(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(200), nullable=False)
    urgency = db.Column(db.String(20), nullable=False)
    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_by = db.relationship('User', foreign_keys=[created_by_id], back_populates='issues')
    assigned_to = db.relationship("IssueAssignment", back_populates="issue", cascade='all, delete-orphan')
    created_on = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    resolved = db.Column(db.Boolean, default=False)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    project = db.relationship('Project', back_populates='issues')
    comments = db.relationship('Comment', back_populates = 'issue')

class IssueAssignment(db.Model):
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)
    issue_id = db.Column(db.Integer, db.ForeignKey('issue.id'), primary_key=True)

    user = db.relationship("User", back_populates="assigned_issues")
    issue = db.relationship("Issue", back_populates="assigned_to")

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.String(200), nullable=False)
    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_by = db.relationship('User', back_populates='comments')
    created_on = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    issue_id = db.Column(db.Integer, db.ForeignKey('issue.id'), nullable=False)
    issue = db.relationship('Issue', back_populates='comments')

    parent_comment_id = db.Column(db.Integer, db.ForeignKey('comment.id'), nullable=True)
    children = db.relationship('Comment', backref=db.backref('parent_comment', remote_side=[id]), lazy='dynamic', join_depth=1)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/', methods=['GET', 'POST'])
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()
        if user:
            return 'An account already exists with that email.'

        hashed_password = generate_password_hash(password)
        user = User(email=email, password=hashed_password)

        with app.app_context():
            db.session.add(user)
            db.session.commit()
            user = User.query.get(user.id)
            session['user_id'] = user.id

        return redirect('/dashboard')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()
        if not user or not check_password_hash(user.password, password):
            return 'Email or password is incorrect.'

        session['user_id'] = user.id

        return redirect("/dashboard")

    return render_template('login.html')

@app.route("/dashboard", methods=['GET', 'POST'])
@login_required
def dashboard():
    user_id = session.get("user_id")
    user = User.query.get(user_id)
    projects = []
    for project_member in user.projects:
        projects.append(project_member.project)

    todo_issues = []
    for project in projects:
        for issue in project.issues:
            if issue.resolved == False and session['user_id'] in [u.user.id for u in issue.assigned_to]:
                todo_issues.append(issue)

    if request.method == 'POST':
        project_id = request.form.get('project_id')
        project = Project.query.get(project_id)

        if project:
            return redirect('project_issues.html', project_id = project_id)
    return render_template('dashboard.html', projects=projects, todo_issues=todo_issues)


@app.route("/project/<int:project_id>/issues", methods=["GET", "POST"])
@login_required
def project_issues(project_id):
    project = Project.query.get(project_id)

    if not project:
        return "Project not found", 404

    # Order issues by unresolved first, then urgency, then created_at (oldest first)
    issues = Issue.query.filter_by(project_id=project_id).outerjoin(IssueAssignment).order_by(
        case((Issue.resolved == False, 0), else_=1).asc(),
        case((Issue.urgency == 'High', 3),
             (Issue.urgency == 'Medium', 2),
             (Issue.urgency == 'Low', 1),
             else_=0
        ).desc(),
        Issue.created_on.asc()
    ).all()
    return render_template("project_issues.html", project=project, issues=issues, project_id=project_id)


@app.route("/project/<int:project_id>/create_issue", methods=["GET", "POST"])
@login_required
def new_issue(project_id):
    form = IssueForm(project_id)
    if form.validate_on_submit():
        title = form.title.data
        description = form.description.data
        urgency = form.urgency.data
        assigned_to_ids = form.assigned_to.data
        created_by_id = session.get('user_id')
        resolved = form.resolved.data

        issue = Issue(
            title=title,
            description=description,
            urgency=urgency,
            created_by_id=created_by_id,
            project_id=project_id,
            resolved=resolved
        )

        for user_id in assigned_to_ids:
            user = User.query.get(user_id)
            issue_assignment = IssueAssignment(user=user)
            issue.assigned_to.append(issue_assignment)

        db.session.add(issue)
        db.session.commit()

        return redirect(f'/project/{project_id}/issues')

    return render_template('new_issue.html', form=form, project_id=project_id)

class IssueForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[DataRequired()])
    urgency = SelectField('Urgency', choices=[('Low', 'Low'), ('Medium', 'Medium'), ('High', 'High')], validators=[DataRequired()])
    assigned_to = SelectMultipleField('Assign To', coerce=int, option_widget=CheckboxInput(), widget=ListWidget(prefix_label=False))
    unassign = SelectMultipleField('Unassign', coerce=int, option_widget=CheckboxInput(), widget=ListWidget(prefix_label=False))
    resolved = BooleanField('Resolved', default=False)
    submit = SubmitField('Update Issue')

    def __init__(self, project_id, issue=None, *args, **kwargs):
        super().__init__(obj=issue, *args, **kwargs)
        project_members = ProjectMember.query.filter_by(project_id=project_id).all()
        user_ids = [member.user_id for member in project_members]
        if issue:
            assigned_user_ids = [assignment.user_id for assignment in issue.assigned_to]
            assigned_users = User.query.filter(User.id.in_(assigned_user_ids)).all()
            unassigned_users = User.query.filter(User.id.in_(user_ids)).filter(not_(User.id.in_(assigned_user_ids))).all()

            self.assigned_to.choices = [(user.id, user.email) for user in unassigned_users]
            self.unassign.choices = [(user.id, user.email) for user in assigned_users]

            self.title.data = issue.title
            self.description.data = issue.description
            self.urgency.data = issue.urgency

        else:
            users = User.query.filter(User.id.in_(user_ids)).all()
            choices = [(user.id, user.email) for user in users]
            self.assigned_to.choices = choices
            self.unassign.choices = []

@app.route("/create_project", methods=['GET', 'POST'])
@login_required
def create_project():
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        admin_id = session.get('user_id')
        admin = User.query.filter_by(id = admin_id).first()
        project = Project(name=name, description=description, admin = admin)
        project_member = ProjectMember(user = admin, project = project)
        db.session.add(project)
        db.session.add(project_member)
        db.session.commit()

        return redirect("/dashboard")

    return render_template('create_project.html')

class AddPeopleToProjectForm(FlaskForm):
    email = StringField("Emails of users to add (separated by comma)", validators=[DataRequired()])

    submit = SubmitField("Add")

@app.route('/logout')
@login_required
def logout():
    session.pop('user_id', None)
    return redirect('/login')

@app.route('/project/<int:project_id>/issue/<int:issue_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_issue(project_id, issue_id):
    issue = Issue.query.get_or_404(issue_id)

    if session['user_id'] != issue.created_by_id and session['user_id'] not in [u.user.id for u in issue.assigned_to]:
        abort(403)

    if request.method == 'POST':
        formdata = MultiDict(request.form)
        form = IssueForm(project_id, issue=issue, formdata=formdata)
        if form.validate_on_submit():
            # Remove assignments for users who have been marked as unassigned
            for assignment in issue.assigned_to:
                if assignment.user_id in form.unassign.data:
                    db.session.delete(assignment)

            # Assign the issue to the new users
            for user_id in form.assigned_to.data:
                if not IssueAssignment.query.filter_by(user_id=user_id, issue_id=issue.id).first():
                    db.session.add(IssueAssignment(user_id=user_id, issue=issue))
            
            # Update issue with form data
            issue.title = form.title.data
            issue.description = form.description.data
            issue.resolved = form.resolved.data

            # Mark issue as resolved if requested
            if form.resolved.data:
                issue.resolved = True
            else:
                issue.resolved = False

            db.session.commit()

            return redirect(url_for('issue_dashboard', project_id=project_id, issue_id=issue_id))
    else:
        form = IssueForm(project_id, issue=issue)

    return render_template('edit_issue.html', issue=issue, form=form)


@app.route("/project/<int:project_id>/add_people", methods=["GET", "POST"])
@login_required
def add_people_to_project(project_id):
    form = AddPeopleToProjectForm()
    project = Project.query.get(project_id)

    if form.validate_on_submit():
        emails = form.email.data.split(",")
        for email in emails:
            email = email.strip()
            user = User.query.filter_by(email=email).first()

            if user:
                if ProjectMember.query.filter_by(project_id=project_id, user_id=user.id).first():
                    continue

                project_member = ProjectMember(project_id=project_id, user_id=user.id)
                db.session.add(project_member)
                send_email(to=user.email, subject="You have been added to a new project!",
                           message=f"You have been added to the '{project.name}' project.")

            else:
                send_email(to=email, subject="You have been invited to a new project!",
                           message=f"You have been invited to join the '{project.name}' project. To join, please sign up on the platform.")
        db.session.commit()
        return redirect(f'/project/{project_id}/issues')
    return render_template('add_people_to_project.html', form=form, project_id=project_id)

class CommentForm(FlaskForm):
    description = StringField('Comment', validators=[DataRequired()])
    submit = SubmitField('Add Comment')

@app.route("/project/<int:project_id>/issue/<int:issue_id>")
@login_required
def issue_dashboard(project_id, issue_id):
    issue = Issue.query.get_or_404(issue_id)
    comments = Comment.query.filter_by(issue_id=issue_id).all()
    form = CommentForm()
    return render_template("issue_dashboard.html", project_id=project_id, issue_id=issue_id, issue=issue, comments=comments, form=form)


@app.route("/project/<project_id>/issue/<issue_id>/create_comment", methods=["GET", "POST"])
@login_required
def create_comment(project_id, issue_id):
    issue = Issue.query.filter_by(id=issue_id).first()

    if not issue:
        return "Issue not found", 404

    form = CommentForm()

    if form.validate_on_submit():
        comment = Comment(
            description=form.description.data,
            created_by_id=session["user_id"],
            issue_id=issue_id,
            parent_comment_id=None
        )
        db.session.add(comment)
        db.session.commit()
        return redirect(url_for('issue_dashboard', project_id=project_id, issue_id=issue_id))

    return render_template("create_comment.html", form=form, project_id=project_id, issue=issue)

@app.route("/project/<int:project_id>/issue/<int:issue_id>/comment/<int:comment_id>/reply", methods=["GET", "POST"])
@login_required
def reply_to_comment(project_id, issue_id, comment_id):
    comment = Comment.query.get_or_404(comment_id)

    if request.method == "POST":
        form = CommentForm()
        if form.validate_on_submit():
            reply = Comment(description=form.description.data,
                            created_by_id=session["user_id"],
                            issue_id=issue_id,
                            parent_comment=comment)
            db.session.add(reply)
            db.session.commit()
            return redirect(url_for('issue_dashboard', project_id=project_id, issue_id=issue_id))
    else:
        form = CommentForm()

    return render_template("reply_to_comment.html", project_id=project_id, issue_id=issue_id, parent_comment=comment, form=form)

def send_email(to, subject, message):
    try:
        gmail_user = "zuranaftab14@gmail.com"  
        gmail_password = "mtivmkbbocjvwfwa"  
        
        msg = MIMEText(message)
        msg['Subject'] = subject
        msg['To'] = to
        
        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        server.ehlo()
        server.login(gmail_user, gmail_password)
        server.sendmail(gmail_user, to, msg.as_string())
        server.close()
        
        print(f"Email sent to {to}")
    except Exception as e:
        print(f"Failed to send email to {to}. Error: {e}")


###### In Progress, Incomplete: 

@app.route('/github_login')
def github_login():
    # Redirect to GitHub for authentication
    return github.authorize_redirect(redirect_uri=url_for('github_authenticate', _external=True))

@app.route('/github_authenticate')
def github_authenticate():
    # Verify and handle the response from GitHub
    token = github.authorize_access_token()
    user = User.query.get(session.get('user_id'))
    
    # Store the GitHub ID in the database for the current user
    
    user.github_access_token = token
    db.session.commit()

    return redirect('/dashboard')

@app.route('/import_github_repo', methods=['GET', 'POST'])
@login_required
def import_github_repo():
    if request.method == 'POST':
        # Get the repo link from the form data
        current_user = User.query.get(session.get('user_id'))
        repo_link = request.form['repo_link']

        # Make a request to the GitHub API to get information about the repo
        headers = {'Authorization': f'token {current_user.github_access_token}'}
        response = requests.get(f'{repo_link}/contents', headers=headers)

        # If the response is not successful, return an error message
        if response.status_code != 200:
            return redirect(url_for('dashboard'))

        # Extract the repo name and description from the response
        repo_name = response.json()[0]['name']
        repo_description = response.json()[0]['description']

        # Create a new project with the repo name and description
        project = Project(name=repo_name, description=repo_description, admin=current_user)
        db.session.add(project)
        db.session.commit()

        # Make another request to the GitHub API to get any issues associated with the repo
        response = requests.get(f'{repo_link}/issues', headers=headers)

        # If the response is successful, create new issues for each issue in the repo
        if response.status_code == 200:
            issues = response.json()
            for issue in issues:
                title = issue['title']
                description = issue['body']
                urgency = 'Medium'  # defualt
                resolved = issue['state'] == 'closed'
                created_by = current_user
                project_id = project.id
                new_issue = Issue(title=title, description=description, resolved = resolved, urgency=urgency, created_by=created_by, project_id=project_id)
                db.session.add(new_issue)
                db.session.commit()

       
        return redirect(url_for('dashboard'))

    return render_template('import_github_repo.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
