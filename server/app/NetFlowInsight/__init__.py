from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from os import path

# Initializing SQLAlchemy object
db = SQLAlchemy()
# Naming the database
DB_NAME = "netflowinsight.db"


#creating the Flask app

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = "SECRET"
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_NAME}'
    db.init_app(app)
    



    from .views import views
    from .auth import auth
    from .models import User, PcapLoc, LogAnalysis, FileAnalysis, Notes, FileResult


    app.register_blueprint(views, url_prefix='/')
    app.register_blueprint(auth, url_prefix='/')
    
    with app.app_context():
        try:
            if not path.exists('instance/'+ DB_NAME):
                db.create_all()
                print("--- Database Created ---")
        except Exception as e:
            print(f"{e}")

    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(id):
        return User.query.get(int(id))

    return app 
        


