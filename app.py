from myproject import app,db,socketio
from flask import render_template, redirect, request, url_for, flash,abort
from flask_login import login_user,login_required,logout_user,current_user
from myproject.models import User,UIDS,RequestUIDS,PUIDS,Info
from myproject.forms import LoginForm, RegistrationForm
from werkzeug.security import generate_password_hash, check_password_hash
from random import randint
import time
from flask_socketio import  send,emit

@socketio.on('myconnection')
def test_connect(msg):
    print(msg)

@socketio.on('fetchUID')
def fetchUID(aid):
    # TODO: added to request queue
    caid=RequestUIDS(ruid=aid)
    db.session.add(caid)
    db.session.commit()
    print('AID: ',aid, 'Requesting: ')

    time.sleep(1)
    # Puppy.query.all()
    aid=RequestUIDS.query.all()
    if aid[0].ruid:
        db.session.delete(aid[0])
        db.session.commit()

# TODO: to delete the uid that is processed
    uids=UIDS.query.all()
    if uids:
        db.session.delete(uids[0])
        db.session.commit()

# TODO: to push uid to processed uid
        puid=PUIDS(uids[0].uid)
        db.session.add(puid)
        db.session.commit()

# TODO: add the info into table
        dateOfAnnotation=time.ctime()
        info=Info(str(current_user.id),str(uids[0].uid),dateOfAnnotation)
        db.session.add(info)
        db.session.commit()

        print('Allocated: '+ str(uids[0].uid))
        emit('fetchUIDAnswer',uids[0].uid)
    else:
        emit('fetchUIDAnswer',"None Allocated! Please Wait")

@socketio.on('pushebackUID')
def pushebackUID(uid):
    # TODO: get the uid last added to info table by current_user
    # and push it back to uid and
    # delete the same from puid
    current_userAID=current_user.id
    # get last updated value of current user
    uid=Info.query.filter_by(aid=str(current_userAID)).order_by(Info.dateOfAnnotation.desc()).first()
    if uid is not None:
        # delete from info
        db.session.delete(uid)
        db.session.commit()

        # delete from puids
        puid=PUIDS.query.filter_by(puid=uid.uid).first()
        db.session.delete(puid)
        db.session.commit()

        # insert to info
        uid=UIDS(uid=uid.uid)
        db.session.add(uid)
        db.session.commit()

@app.route('/')
def home():
    return render_template('home.html')

# @app.route('/annotationtool')
# @login_required
# def annotation():
#     return render_template('AnnotationTool.html')

@app.route('/annotation')
@login_required
def annotationtool():
    random_number = randint(1, 1000)
    return render_template('annotationtool.html',aid=current_user.id)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You logged out!')
    return redirect(url_for('home'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        # Grab the user from our User Models table
        user = User.query.filter_by(email=form.email.data).first()

        # Check that the user was supplied and the password is right
        # The verify_password method comes from the User object
        # https://stackoverflow.com/questions/2209755/python-operation-vs-is-not

        if user.check_password(form.password.data) and user is not None:
            #Log in the user

            login_user(user)
            flash('Logged in successfully.')

            # If a user was trying to visit a page that requires a login
            # flask saves that URL as 'next'.
            next = request.args.get('next')

            # So let's now check if that next exists, otherwise we'll go to
            # the welcome page.
            if next == None or not next[0]=='/':
                next = url_for('annotationtool')

            return redirect(next)
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()

    if form.validate_on_submit():
        user = User(email=form.email.data,
                    username=form.username.data,
                    password=form.password.data)

        db.session.add(user)
        db.session.commit()
        flash('Thanks for registering! Now you can login!')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

if __name__ == '__main__':
    # for i in range(1,100):
    #     t=UIDS(i)
    #     db.session.add(t)
    # db.session.commit()
    socketio.run(app)
