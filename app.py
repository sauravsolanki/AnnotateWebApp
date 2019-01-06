from myproject import app,db,socketio
from flask import render_template, redirect, request, url_for, flash,abort,jsonify
from flask_login import login_user,login_required,logout_user,current_user
from myproject.models import User,UIDS,RequestUIDS,PUIDS,Info,ImageLinks
from myproject.forms import LoginForm, RegistrationForm
from werkzeug.security import generate_password_hash, check_password_hash
from random import randint
import time
from flask_socketio import  send,emit
from flask_pymongo import PyMongo,MongoClient
from flask import Response
from bson.json_util import loads
import json
app.config["MONGO_URI"] = "mongodb://localhost:27017/annotate"
mongo = PyMongo(app)
n=14
@socketio.on('myconnection')
def test_connect(msg):
    print(msg)

@socketio.on('fetchUID')
def fetchUID(aid):
    global n
    #  added to request queue
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

#  to delete the uid that is processed
    uids=UIDS.query.all()
    if uids:
        db.session.delete(uids[0])
        db.session.commit()
        # not for deploy ,comment it
        # db.session.add(uids[0].uid)
        # db.session.commit()
        # till here

#  to push uid to processed uid
        puid=PUIDS(uids[0].uid)
        db.session.add(puid)
        db.session.commit()


#   send the image links also
        imagelink=ImageLinks.query.filter_by(id=int(uids[0].uid)).first()
        print('Allocated: '+ str(imagelink.links))

#  add the info into table
        dateOfAnnotation=time.ctime()
        # TODO:Info database, mark status Column as "in_process"
        status="in_process"
        info=Info(str(current_user.id),str(uids[0].uid),status,dateOfAnnotation,str(imagelink.links))
        db.session.add(info)
        db.session.commit()

        # emit('fetchUIDAnswer',uids[0].uid)
        # TODO(1): send json file from the database
        n=int(uids[0].uid)
        jsonfile = mongo.db.docs.find_one_or_404({"file": n})
        # print(jsonfile)
        jsonfile.pop('_id')
        # jsonfile.pop('file')
        # tochange for mistake
        jsonfile=json.dumps(jsonfile)

        # r = json.dumps(jsonfile)
        # print(type(r)) #Output str
        # loaded_r = json.loads(r)
        # print(type(loaded_r)) #Output dict
        # t=json.load(json.dumps(jsonfile))

        emit('fetchUIDAnswer',str(jsonfile))
    else:
        emit('fetchUIDAnswer',"None Allocated! Please Wait")

# @socketio.on('json')
# def handle_json(json):
#     print('received json: ' + str(json))

@socketio.on('mydata')
def mydata(data):

    print(type(data)) # <class 'str'>
    # print('received data: ' + (data))
    # global n
    jsonfile=json.loads(data)
    # print(jsonfile)
    n=int(jsonfile['file'])
    print("current file annotated "+str(n)+"by User Id :"+ str(current_user.id) )
    # due to presence of object id ,update operation not working
    # TODO(4):
    mongo.db.docs.delete_one({"file":n})
    mongo.db.docs.insert(jsonfile,check_keys=False)
    # TODO:In Info database, update the corresponding uid column status as "annotated"
    # it has data.file(uid)(here it is n variable ) and here we have str(current_user.id) as aid
    status="annotated"
    temp = Info.query.filter_by(uid=str(n),aid=str(current_user.id)).first()
    temp.status=status
    db.session.commit()
    # first_puppy = Puppy.query.filter_by(age=107,name='Sammy').first()
    # first_puppy.age = 180
    # db.session.commit()

    # d = json.load(data)
    #mongo.db.docs.update_one({"file":3},{"$set": d}, upsert=True)
    # mongo.db.docs.update_one({"file":11},{"$set": data }, upsert=True)

@socketio.on('update')
def update(json_data):
    #w=1, upsert=True
    # mongo.db.docs.update_one({"file":3},{"$set": {"file":10}}, upsert=True)
    # return "Update Successful!"
    # update nth file
    d = json.load(json_data)
    mongo.db.docs.update_one({"file":n},{"$set": d}, upsert=True)
    # return redirect(url_for("annotationtool"))


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
    # for i in range(1,792):
    #     t=UIDS(i)
    #     db.session.add(t)
    # db.session.commit()
    # db.create_all()
    socketio.run(app)
