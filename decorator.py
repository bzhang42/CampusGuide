from functools import wraps
from flask import flash, redirect, url_for

def check_confirmed(func)
	@wraps(func)
	def decorated_function(*args,**kwargs):
		status = db.execute("SELECT confirmed FROM users WHERE :user_id", user_id = session[user_id])[0]['confirmed']
		if status == 0:
			flash("Please confirm your account!", "warning")
			return redirect("/unconfirmed")
		return func(*args, **kwargs)
	return decorated_function