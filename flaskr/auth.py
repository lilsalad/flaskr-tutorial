import functools

from flask import (Blueprint, flash, g,redirect, render_template, request, session, url_for)

from werkzeug.security import check_password_hash, generate_password_hash

from flaskr.db import get_db

bp = Blueprint('auth',__name__,url_prefix = '/auth')

@bp.route('/register', methods = ('GET','POST'))
def register():
    if request.method =='POST':
        username =request.form['username']
        password =request.form['password']
        db=get_db()
        error = None

        if not username:
            error = 'Username is required!'
        elif not password:
            error = 'Password is required!'
        
        if error is None:
            try:
                db.execute( "INSERT INTO user (username, password) VALUES (?, ?)",
                    (username, generate_password_hash(password)),
                )
                db.commit()
            except db.IntegrityError:
                error = f"User {username} is already registered."
                #F-strings provide a way to embed expressions inside string literals,
                # using a minimal syntax. It should be noted that an f-string is 
                # really an expression evaluated at run time, not a constant value.
                # In Python source code, an f-string is a literal string, prefixed 
                # with 'f', which contains expressions inside braces.
            else:
                return redirect(url_for('auth.login'))
        flash (error)

    return render_template('auth/register.html')


