Issue Tracker
This is an issue tracker web application built with Flask and SQLAlchemy. Users can create projects, add members to projects, create issues, assign issues to project members, and comment on issues.

Features
User registration and authentication
Email notification when added to a project
Project creation and management
Issue creation and management
Issue assignment to project members
Commenting on issues

The application is currently incomplete. I plan to add roles and user-performance model, whereby the appplciation tracks the number of comments, resolved issues etc. to generate graphs. Hopefully, down the line I also learn some front-end development to make the application more user friendly. 

Models
User: represents a registered user
Project: represents a project created by a user
ProjectMember: represents a user who is a member of a project
Issue: represents an issue created by a user for a project
IssueAssignment: represents an assignment of an issue to a project member
Comment: represents a comment made by a user on an issue

Demo
[Insert link to demo video here]

Getting Started
To run the application locally, follow these steps:

Clone the repository: git clone https://github.com/username/issue-tracker.git
Install the dependencies: pip install -r requirements.txt
Set up the database: flask db upgrade
Start the development server: flask run
Contributing
Contributions are welcome! If you encounter any bugs or issues, please create an issue in the issue tracker. If you have any feature requests or would like to contribute code, please create a pull request.

License
This project is licensed under the MIT License.
