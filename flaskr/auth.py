import functools

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash

from flaskr.db import get_db
a1='1212'
bp = Blueprint('auth', __name__, url_prefix='/auth')

@bp.route('/register', methods=('GET', 'POST'))
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None

        if not username:
            error = 'Username is required.'
        elif not password:
            error = 'Password is required.'

        if error is None:
            try:
                db.execute(
                    "INSERT INTO user (username, password) VALUES (?, ?)",
                    (username, generate_password_hash(password)),
                )
                db.commit()
            except db.IntegrityError:
                error = f"User {username} is already registered."
            else:
                return redirect(url_for("auth.login"))

        flash(error)

    return render_template('auth/register.html')




@bp.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None
        user = db.execute(
            'SELECT * FROM user WHERE username = ?', (username,)
        ).fetchone()

        if user is None:
            error = 'Incorrect username.'
        elif not check_password_hash(user['password'], password):
            error = 'Incorrect password.'

        if error is None:
            session.clear()
            session['user_id'] = user['id']
            return redirect(url_for('index'))

        flash(error)

    return render_template('auth/login.html')

@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id')

    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute(
            'SELECT * FROM user WHERE id = ?', (user_id,)
        ).fetchone()

@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))

        return view(**kwargs)

    return wrapped_view


@bp.route('/test',methods=('GET','POST'))

def uploadurl():
    if request.method == 'POST':
        url = request.form['url']
        # db = get_db()
        # error = None
        # user = db.execute(
        #     'SELECT * FROM user WHERE username = ?', (username,)
        # ).fetchone()
 
        if url is None:
            error = 'a required url'
        else:
            runurl(url)

    return render_template('auth/test.html')
def runurl(url1):
    import hashlib
    import hmac
    import urllib
    import time 

    AK = "694c1c500fd6416eb207a59a13bc0e55"
    SK = "75a0418db8144bb49356ae4ea3163fbd"
    host = "vca.bj.baidubce.com"
    method = "PUT"
    URI = "/v2/image"
    query = "sync"

    x_bce_date = time.gmtime()
    x_bce_date = time.strftime('%Y-%m-%dT%H:%M:%SZ',x_bce_date)
    '''print(x_bce_date)'''

    header={
        "content-type":"application/json",
        "Host":host,
        "x-bce-date":x_bce_date
            }
    signedHeaders = "content-type;host;x-bce-date"

    authStringPrefix="bce-auth-v1" + "/" + AK + "/" + x_bce_date +"/" + "60"

    CanonicalURI = urllib.parse.quote(URI)
    CanonicalQueryString = query + "="

    result = []
    for key,value in header.items():
        tempStr = str(urllib.parse.quote(key.lower(),safe=""))+":"+str(urllib.parse.quote(value,safe=""))
        result.append(tempStr)
    result.sort()

    CanonicalHeaders = "\n".join(result)
    CanonicalRequest = method + "\n" + CanonicalURI + "\n"  + CanonicalQueryString + "\n" + CanonicalHeaders

    print(CanonicalRequest)

    signingKey = hmac.new(SK.encode('utf-8'),authStringPrefix.encode('utf-8'),hashlib.sha256)

    Signature= hmac.new((signingKey.hexdigest()).encode('utf-8'),CanonicalRequest.encode('utf-8'),hashlib.sha256)

    header['Authorization'] = authStringPrefix + "/" +signedHeaders+"/"+Signature.hexdigest()

    import requests
    import json

    body ={
        "source": "{}".format(url1) #图片来源 可以为url 也可以使用各个云的存储访问地址 但必须要有访问权限
    }

    url = "http://" + host +URI +"?"+query
    r=requests.put(url,headers=header,data=json.dumps(body))
    print(r.text)
    return r.text


@bp.route('/sosuo',methods=('GET','POST'))

def teset11():
    return render_template('auth/sosuo.html')
