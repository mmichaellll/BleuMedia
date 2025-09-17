from sqlalchemy import create_engine, text, Column, String, Integer, ForeignKey, DateTime, or_, desc, func
from sqlalchemy.orm import sessionmaker, declarative_base
from flask import Flask, flash, request, redirect, render_template, url_for, session, send_from_directory
from datetime import datetime
import secrets
import hashlib
from functools import wraps
import os
from werkzeug.utils import secure_filename
from zoneinfo import ZoneInfo
import subprocess
import requests
from dotenv import load_dotenv

load_dotenv()

print(os.getenv("APIKEY"))

app = Flask(__name__)
app.secret_key = 'fe65b4ae8c7a0db9e77a10d7c987ce4f2c9da26bf29e6782'
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.config["TEMP_UPLOAD_FOLDER"] = 'temp'
app.config["UPLOAD_FOLDER"] = 'uploads'

engine = create_engine("sqlite:///media.db")
Session = sessionmaker(bind=engine)
Base = declarative_base()

# user
class Users(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, nullable=False)
    email = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)
    password_salt = Column(String, nullable=False)
    created = Column(DateTime, nullable=False)

# piece of media (video)
class Media(Base):
    __tablename__ = "media"
    id = Column(Integer, primary_key=True)
    user_id = Column(ForeignKey("users.id"))
    filename = Column(String, nullable=False)
    filepath = Column(String, nullable=False)
    media_type = Column(String, nullable=False)
    uploaded_at = Column(DateTime, nullable=False)
    title = Column(String, nullable=False)
    thumbnail_path = Column(String, nullable=False)
    last_watched = Column(DateTime)

# tags for categorising media
class Tags(Base):
    __tablename__ = "tags"
    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    user_id = Column(ForeignKey("users.id"),nullable=False)

# links media items to tags
class MediaTags(Base):
    __tablename__ = "media_tags"
    media_id = Column(ForeignKey("media.id"),primary_key=True, autoincrement=False)
    tag_id = Column(ForeignKey("tags.id"), primary_key=True, autoincrement=False)

# creates tables in db if it doesnt exist, good for testing so i can quickly delete db and remake
Base.metadata.create_all(engine)

def allowed_file(filename):
    """ checks if file uploaded ends with one of those extensions for video """
    return filename.lower().endswith(('.mp4','.mov','.avi', '.webm'))


def remove_extension(filename):
    """ removes extension of the filename """
    allowed_extensions = ('.mp4','.mov','.avi', '.webm') # these are the extensions that are most common
    for ext in allowed_extensions: # loop through allowed extensions
        if filename.lower().endswith(ext): # if file ends with extension
            return filename[:-len(ext)] # remove the extension from filename and return
    return filename # return filename if no extension

def update_username(user,new_username):
    stripped_user = new_username.strip()
    if not stripped_user or stripped_user == user.username: # if username is the same
        return False, "Please enter a new username to update"
    with Session() as db_session:
        if db_session.query(Users).filter(Users.username == stripped_user, Users.id != user.id).first(): # if username already taken
            return False, "Username already taken"
        user.username = stripped_user # update user if it is different and unique
        return True, "Username updated successfully"


def update_email(user,new_email):
    stripped_email = new_email.strip()
    if not stripped_email or stripped_email == user.email: # if email is the same as current email
        return False, "Please enter a new email to update"
    with Session() as db_session:
        if db_session.query(Users).filter(Users.email == stripped_email, Users.id != user.id).first(): # if email already taken
            return False, "Email already taken" 
        user.email = stripped_email
        return True, "Email updated successfully"

def update_password(user, old_password, new_password, confirm_password):
    if not old_password or not new_password.strip() or not confirm_password: # if field doesn't have data
        return False, "All password fields required."
    if new_password != confirm_password: # if passwords do not match
        return False, "New passwords do not match"
    if not check_password(user.password_hash, user.password_salt, old_password): # if current password is incorrect
        return False, "Current password is incorrect."
    if len(new_password) < 8: # if password is less than 8 characters
        return False, "New password must be at least 8 characters."
    hashed_pwd, salt = hash_password(new_password) # hash password
    user.password_hash = hashed_pwd # update hash
    user.password_salt = salt # update salt
    return True, "Password updated successfully"

def remove_media_file(db_session, media_id):
    """ deleted media record off table + file + thumbnail + tags """
    # find media in the db
    media_to_delete = db_session.query(Media).filter_by(id=media_id, user_id=session['user_id']).first()
    if media_to_delete:
        # if the filepath exists, delete media
        if os.path.exists(media_to_delete.filepath):
            os.remove(media_to_delete.filepath)
        # if filepath exists, delete thumbnail
        if os.path.exists(media_to_delete.thumbnail_path):
            os.remove(media_to_delete.thumbnail_path)
        # delete all tags associated with the media
        tags_to_delete = db_session.query(MediaTags).filter_by(media_id=media_id).delete()
        # delete the media out of the db
        db_session.delete(media_to_delete)
        db_session.commit() # commit to the db
        flash(f"Successfully deleted '{media_to_delete.title}'!")
        return True
    else:
        flash("Could not find the file to delete")
        return False

def login_required(f):
    """Decorate routes to require login."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            flash("You must be logged in to access this page")
            return redirect(url_for("index"))
        return f(*args, **kwargs)
    return decorated_function



def aus_time_now():
    """ returns time in Australia/Sydney timezone """
    return datetime.now(ZoneInfo("Australia/Sydney")) # i need it in Sydney Australia TZ because thats where my client lives
    # so the 'last_watched' time should reflect their timezone


def hash_password(password):
    """ hash password + salt using sha256 """
    # Generate 16 byte hex string for salt
    salt = secrets.token_hex(16)
    # combine salt with pwd
    salted_pwd = salt + password
    # hash password with sha256 and return the hexdigest
    hashed_pwd = hashlib.sha256(salted_pwd.encode()).hexdigest()
    # return salt + hashed_passwd to store
    return hashed_pwd, salt



def check_password(stored_hash, stored_salt, password):
    """ verify password with one stored hash + salt """
    salted_pwd = stored_salt + password # add stored salt and password to get the salted password
    hashed_pwd = hashlib.sha256(salted_pwd.encode()).hexdigest() # hash the result 
    return hashed_pwd == stored_hash # see if its the same as the users password input

@app.route('/media_info/<media_id>', methods=["GET","POST"])
@login_required
def media_info(media_id):
    # display info about a media item
    TMDB_API_KEY = os.getenv("APIKEY") # get tmdb api key from .env file
    TMDB_BASE_URL = 'https://api.themoviedb.org/3' # base url for api calls
    TMDB_IMAGE_BASE = 'https://image.tmdb.org/t/p/w500' # base url for posters
    tmdb_result = None # if tmdb data was found
    tmdb_id = None # the movie id on tmdb
    tmdb_poster_url = None # the full url of the movie poster
    with Session() as db_session:
        media = db_session.query(Media).filter_by(id=media_id, user_id=session['user_id']).first() # see if media exist a
        if not media: # if doesnt exist redirect
            flash("Media not found or you dont have permission to view it!")
            return redirect(url_for('library'))
        # get all tag ids associated with media item
        tag_ids = db_session.query(MediaTags.tag_id).filter_by(media_id=media.id).all()
        tag_ids = [tag_id[0] for tag_id in tag_ids] # convert list of tuples to list
        tags = []
        if tag_ids:
            # if tags exist, then get their name from tag table
            tags = [t.name for t in db_session.query(Tags).filter(Tags.id.in_(tag_ids)).all()]
        try:
            # make get request to TMDB search using the media title
            resp = requests.get(f'{TMDB_BASE_URL}/search/movie', params={'api_key':TMDB_API_KEY,'query':media.title})
            if resp.status_code == 200:
                data = resp.json()
                # if search returns any results, use the first one
                if data.get('results'):
                    movie = data['results'][0]
                    tmdb_result = True
                    tmdb_id = movie['id']
                    # if poster is avliable, use it
                    if movie.get('poster_path'):
                        tmdb_poster_url = f"{TMDB_IMAGE_BASE}{movie['poster_path']}"
        except Exception:
            # if api fails, ignore it
            pass

        if request.method == "POST" and 'use_tmdb_poster' in request.form and tmdb_poster_url:
            # handle post request if user submits form to use TMDB poster instead
            # thumb_ext = tmdb_poster_url.split('.')[-1].split('?')[0] # extract file extension
            thumb_filename = f"{media.id}_tmdb_thumb.jpg"
            thumb_path = os.path.join(app.config['UPLOAD_FOLDER'],'thumbnails',thumb_filename)
            os.makedirs(os.path.dirname(thumb_path), exist_ok=True) # create thumbnail directory if it doesnt exist
            try:
                # download poster image from the URL
                response = requests.get(tmdb_poster_url)
                response.raise_for_status() # raise error if download failed

                # save image to new thumbnail path
                with open(thumb_path,'wb') as f:
                    f.write(response.content)
                # update media record 
                media.thumbnail_path = os.path.relpath(thumb_path) # store in relative to current working dir, not abso path
                db_session.commit() # commit to db
                flash("TMDB poster set as thumbnail")
                # redirect to same page to show updated thumbnail
                return redirect(url_for('media_info',media_id=media.id))
            except Exception as e:
                # if fail, show error
                flash(f"Failed to set TMDB poster as thumbnail: {e}")
        return render_template('media_info.html', media=media, tags=tags, tmdb_result=tmdb_result, tmdb_id=tmdb_id, tmdb_poster_url=tmdb_poster_url)
@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    """ serves uploaded files from the upload folder"""
    # uses flask send_from_directory to provide file access from a specific directory securely
    return send_from_directory(app.config['UPLOAD_FOLDER'],filename)

@app.route('/watch/<media_id>')
@login_required
def watch(media_id):
    """ display video watch page for a media item """
    print(f"id: {media_id}")
    with Session() as db_session:
        # find the video in the db that matches the media id + user id to make sure they have permission + it exists
        video = db_session.query(Media).filter_by(id=media_id, user_id=session['user_id']).first()
        # if not found or user doesn't own it, then return to dashboard
        if not video:
            flash("Video not found, or do not have permission to view")
            return redirect(url_for('dashboard'))
        # update last_watched time to current time now
        video.last_watched = aus_time_now()
        db_session.commit()
        return render_template('watch.html',item=video)

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/dashboard', methods=["GET","POST"])
@login_required
def dashboard():
    """ main user dashboard, shows recent media the user uploaded or watched last"""

    with Session() as db_session:
        # post request to see if user wants to remove file
        if request.method == 'POST':
            if 'remove_file' in request.form:
                media_id = request.form.get('remove_file')
                remove_media_file(db_session, media_id) # calls function to remove that item
                return redirect(url_for('dashboard')) # refresh page after removal
        # try to first get recently watched media, and get 5
        user = db_session.query(Users).filter_by(id = session['user_id']).first()
        recent_media = db_session.query(Media).filter(Media.last_watched.isnot(None), Media.user_id==session['user_id']).order_by(desc(Media.last_watched)).limit(5).all()
        # if they dont have any recently watched media, it gives them 5 recently uploaded items
        if not recent_media:
            recent_media = db_session.query(Media).filter_by(user_id=session['user_id']).order_by(desc(Media.uploaded_at)).limit(5).all()
            # if no media, then flash message to tell user
            if not recent_media:
                flash("You haven't uploaded any media!")
    return render_template('dashboard.html', media=recent_media, username=user.username)


@app.route('/register', methods=["GET", "POST"])
def register():
    """ handles registration """
    if request.method == "POST":
        # get user input in forms
        username = request.form['username'].strip()
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        email = request.form['email'].strip()

        if not username or not password.strip() or not confirm_password or not email: # make sure all field filled
            flash("All fields are required and cannot be empty space!")
            return redirect(url_for('register'))

        if len(password) < 8:
            flash("Passwords must be at least 8 characters long!")
            return redirect(url_for('register'))
        
        if password != confirm_password:
            flash("Passwords do not match!")
            return redirect(url_for('register'))

        with Session() as db_session:
            # checks if username/email is already taken
            user_exists = db_session.query(Users).filter(or_(Users.username == username, Users.email == email)
            ).first() # see if username or email exists in db
            if user_exists:
                flash('Username or email already exists!')
                return redirect(url_for('register'))
            hashed_pwd, salt = hash_password(password) # hash password
            # create new user obj
            new_user = Users(
                username=username,
                email=email,
                password_hash=hashed_pwd,
                password_salt=salt,
                created=aus_time_now()
            )
            # add new user obj to session + commit to db
            db_session.add(new_user)
            db_session.commit()
            # auto login the user by setting id
            session['user_id'] = new_user.id
            flash("Registration Successful!")
            return redirect(url_for('dashboard'))
    return render_template('register.html')

# @app.route('/reset_password')
# def reset_password():
#     pass # ill make this hopefully at some point maybe (maybe send email or something)

@app.route('/login',methods=['GET','POST'])
def login():
    """ handles user login """
    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']
        # dont need email because i got it so i could possibly verify/reset password maybe

        with Session() as db_session:
            # find the user by user name
            user = db_session.query(Users).filter_by(username=username).first()
            # if user exists + the password is correct, log in
            if user and check_password(user.password_hash,user.password_salt,password):
                session['user_id'] = user.id
                flash('Logged in successfully!')
                return redirect(url_for('dashboard'))
        # if not, flash error message
        flash('Invalid password or username')
    return render_template('login.html')


@app.route('/logout')
def logout():
    """ log user out """
    session.pop('user_id', None) # remove userid from the session
    flash("You have been logged out")
    return redirect(url_for('dashboard'))


@app.route('/upload',methods=['GET','POST'])
@login_required
def upload():
    """
    upload files to server
    """
    # make sure upload dirs exist
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs(app.config['TEMP_UPLOAD_FOLDER'], exist_ok=True)
    # get list of files waiting to be uploaded in users session
    temp_uploads = session.get('temp_uploads',[])
    # get all existing tags for the user to suggest in the UI
    with Session() as db_session:
        if 'user_id' in session:
            tags_objects = db_session.query(Tags).filter_by(user_id=session['user_id']).all()
            all_tags = [tag.name for tag in tags_objects]
    if request.method == 'POST':
        # remove file from the temp queue if user presses 'x' button on the UI
        if 'remove_file' in request.form:
            filename_to_remove = request.form['remove_file']
            temp_filepath = os.path.join(app.config['TEMP_UPLOAD_FOLDER'],filename_to_remove)
            # delete file from the temp folder
            if os.path.exists(temp_filepath):
                try:
                    os.remove(temp_filepath)
                    flash(f"Removed '{filename_to_remove}' from upload!") # removing file if user removes it
                except OSError as e:
                    flash(f"Error removing temp file!")
            # remove the file's info from the session list
            updated_uploads = [f for f in temp_uploads if f['name'] != filename_to_remove]
            session['temp_uploads'] = updated_uploads
            return redirect(url_for('upload'))
        # confirming upload / process files
        elif 'confirm_upload' in request.form:
            if not temp_uploads:
                flash("No files to upload!")
                return redirect(url_for('upload'))
            user_id = session['user_id']
            successful_upload = 0 # counts how many uploads are successful to tell the user
 
            with Session() as db_session:
                # process each file in temp upload queue
                for file_info in temp_uploads:
                    original_filename = file_info['name']
                    # create unique storage filename so multiple users can add the same file, as their userid is added
                    name,ext = os.path.splitext(original_filename)
                    # Year month date hour min second microsecond
                    timestamp = aus_time_now().strftime('%Y%m%d%H%M%S%f')
                    storage_filename = f"{user_id}_{name}_{timestamp}{ext}" #combine file to make sure no duplicate files can exist 
                    temp_filepath = os.path.join(app.config['TEMP_UPLOAD_FOLDER'],original_filename) # joins temp upload with original filename
                    final_filepath = os.path.join(app.config['UPLOAD_FOLDER'],storage_filename) # joins final upload folder with storage filename
                    try:
                        # get metadata from the form for this file
                        title = request.form.get(f"title_{original_filename}","").strip()
                        if not title:
                            # if the user doesn't upload title, it defaults to name of file
                            title = remove_extension(original_filename)
                        thumbnail_file = request.files.get(f"thumbnail_{original_filename}")
                        
                        thumbnail_dir = os.path.join(app.config['UPLOAD_FOLDER'],'thumbnails')
                        os.makedirs(thumbnail_dir, exist_ok=True) # make sure thumbnail_dir exists
                        # thumbnail gen
                        if thumbnail_file and thumbnail_file.filename:
                            # if custom thumbnail was uploaded, use that one
                            thumbnail_extension = os.path.splitext(thumbnail_file.filename)[1] # splits into name and extension ([0] = name, [1] = extension)
                            thumbnail_name = f"{os.path.splitext(storage_filename)[0]}_thumb{thumbnail_extension}" # makes new filename for thumbnail: takes the filename + _thumb + thumbnail extention
                            thumbnail_path = os.path.join(thumbnail_dir, thumbnail_name) # makes path where new thumbnail will be stored
                            thumbnail_file.save(thumbnail_path) # saves in thumbnail path
                        else:
                            # if no thumbnail was uploaded, generate one from the first frame of the first second of the video file
                            thumbnail_name = f"{os.path.splitext(storage_filename)[0]}_thumb.png"
                            thumbnail_path = os.path.join(thumbnail_dir, thumbnail_name)
                            print("subprocess start")
                            print(f"temp_filepath: {temp_filepath}, thumbnail_path: {thumbnail_path}")
                            # FFmpeg command to generate thumbnail, using subprocess rather than os.system() because it passes a list of strings, cannot inject
                            # if using os.system(f""), the user could use something like ; rm -rf / ; and it would attempt to delete the system
                            command = ['ffmpeg','-i',temp_filepath,'-ss','00:00:01.000','-vframes:','1',thumbnail_path]
                            print(command)
                            subprocess.run(
                                command,
                                check=True, capture_output=True, text=True 
                                # check = checks the return code of the subprocess, if check is true + return code is not zero 
                                # capture_output = capture the output + errors
                                # text = return stderr as string
                            )
                            print("subprocess end")
                        # move the temp file to final path
                        os.rename(temp_filepath,final_filepath)   
                        # create new media obj to add to db
                        new_media = Media(
                            user_id = user_id,
                            filename = original_filename, # make sure filename displayed is correct, without user id
                            filepath = final_filepath, # stores using user id appened so multiple users can upload same title
                            media_type = 'video',
                            thumbnail_path = thumbnail_path,
                            uploaded_at = aus_time_now(),
                            title = title
                        )

                        db_session.add(new_media)
                        db_session.commit() # commit to get the new_media.id
                        media_id = new_media.id
                        # process + add tags
                        raw_tags = request.form.get(f"tags_{original_filename}","")
                        tags = [tag.strip().lower() for tag in raw_tags.split(',') if tag.strip()]

                        # check if tag already exists for this user
                        for tag_name in tags:
                            tag_obj = db_session.query(Tags).filter_by(name=tag_name, user_id=user_id).first()
                            if not tag_obj:
                                # if not, create it
                                new_tag = Tags(name=tag_name, user_id=user_id)
                                db_session.add(new_tag)
                                db_session.commit()
                                tag_id = new_tag.id
                            else:
                                tag_id = tag_obj.id
                            # create link in media_tags table
                            if not db_session.query(MediaTags).filter_by(media_id=media_id,tag_id=tag_id).first():
                                db_session.add(MediaTags(media_id=media_id, tag_id=tag_id))
                        db_session.commit()
                        successful_upload += 1
                    except subprocess.CalledProcessError as e:
                        # handle ffmpeg errors
                        db_session.rollback()
                        flash(f"Error processing '{original_filename}' with FFmpeg: {e.stderr}")
                        if os.path.exists(temp_filepath):
                            os.remove(temp_filepath)
                        continue
                    except Exception as e:
                        # handle other errors during processing, likely to do with space
                        db_session.rollback()
                        flash(f"Error processing '{original_filename}' for upload: {e}")
                        # clean up the files left if unable to process
                        if os.path.exists(final_filepath):
                            os.remove(final_filepath)
                            os.remove(thumbnail_path)
                        if os.path.exists(temp_filepath):
                            os.remove(temp_filepath)
                            os.remove(thumbnail_path)
                        continue # continue even if some fail
            session.pop('temp_uploads',None) # clear temp uploads after everything finished
            if successful_upload > 0:
             
                flash(f"{successful_upload} file(s) uploaded successfully!")
            return redirect(url_for('upload'))

        # initial file selection from the user's computer
        elif 'files' in request.files:
            new_files = []
            # .getlist() handles multiple file selections, and loop through each file obj
            for file_storage in request.files.getlist('files'):
                if file_storage.filename == '': #skip empty files
                    continue

                # check if file obj exists + has allowed extension
                if file_storage and allowed_file(file_storage.filename):
                    # sanitise filename to prevent security risks like directory traversing
                    filename = secure_filename(file_storage.filename)
                    # path where file will be stored temp
                    temp_filepath = os.path.join(app.config['TEMP_UPLOAD_FOLDER'],filename)
                    try:
                        # save the file to the temp folder
                        file_storage.save(temp_filepath)
                        # get the size of the file
                        file_size = os.path.getsize(temp_filepath)
                        # add file detail to list of new files for this request
                        new_files.append({'name':filename,'size':file_size,'temp_path':temp_filepath})
                        # inform user that the file is ready to be uploaded
                        flash(f"File '{filename}' is ready for upload")
                    except Exception as e:
                        # if some error occurs, it informs the user
                        flash(f"Error uploading '{filename}': {e}")
                        continue
            if new_files:
                # add list of new files to the main list of temp uploads
                temp_uploads.extend(new_files)
                # save upadated list
                session['temp_uploads'] = temp_uploads
            else:
                # if no valid files added, it tells the user
                flash("No valid files!!")
                            
    return render_template('upload.html', temp_uploads=temp_uploads, all_tags=all_tags)


@app.route('/library', methods=["GET","POST"])
@login_required
def library():
    """ shows all user media + search + tag filtering """
    # get search/filter parameters from the URL query string
    query_str = request.args.get('query','')
    selected_tags = request.args.getlist('tags')
    sort = request.args.get('sort','uploaded_desc')

    with Session() as db_session:
        # handle file removal requests from library page
        if request.method == "POST" and 'remove_file' in request.form:
            media_id_to_remove = request.form.get('remove_file')
            remove_media_file(db_session, media_id_to_remove)
            return redirect(url_for('library'))
        # get all unique tags for the current user to display in the filter option
        all_tags_result = db_session.query(Tags.name).filter_by(user_id=session['user_id']).all()
        all_tags = [tag[0] for tag in all_tags_result]
        # start with a base query for all media beloning to current user
        query = db_session.query(Media).filter_by(user_id=session['user_id'])
        # if there is a search string, filter by title (case-insensitive)
        if query_str:
            query = query.filter(Media.title.ilike(f"%{query_str}%"))
        # if tags are selected for filtering, apply this query
        if selected_tags:
            # find find the tag obj that match selected name for the current user
            tag_objs = db_session.query(Tags).filter(Tags.name.in_(selected_tags),Tags.user_id==session['user_id']).all()
            tag_ids = [tag.id for tag in tag_objs] # get their ids
            if tag_ids:
                # find media items that have all of the selected tags
                media_ids = db_session.query(MediaTags.media_id).filter(MediaTags.tag_id.in_(tag_ids)).group_by(MediaTags.media_id).having(func.count(MediaTags.tag_id) == len(tag_ids)).all()
                media_ids = [media_id[0] for media_id in media_ids]
                # filter main query to only include media id
                query = query.filter(Media.id.in_(media_ids))
            else:
                query = query.filter(False) # if selected tags doesnt exist, return no results
        # sorting based on sort parameter
        if sort == 'uploaded_desc':
            query = query.order_by(desc(Media.uploaded_at))
        elif sort == 'uploaded_asc':
            query = query.order_by(Media.uploaded_at)
        elif sort == 'lastwatched_desc':
            query = query.order_by(desc(Media.last_watched))
        elif sort == 'lastwatched_asc':
            query = query.order_by(Media.last_watched.nullsfirst()) # nullsfirst ensures item never watched appear at start
        elif sort == 'title_asc':
            query = query.order_by(Media.title.asc())
        elif sort == 'title_desc':
            query = query.order_by(Media.title.desc())
        user_media = query.all() # execute constructed query to get final list of media
    return render_template('library.html', media=user_media, query=query_str, all_tags=all_tags, selected_tags=selected_tags)


@app.route('/profile',methods=['POST','GET'])
@login_required
def profile():
    """ user profile page to change username/email/password """
    user_id = session['user_id']
    with Session() as db_session:
        user = db_session.query(Users).filter_by(id=user_id).first() # get user data from db
        if not user: # if user doesnt exist / invalid user id
            flash("User not found.")
            return redirect(url_for('dashboard'))
        if request.method == "POST":
            # check if anythinghas changed
            has_changed = False
            # check if the submitted form was for updating the username/email
            if 'update_profile' in request.form:
                # get a new username / email from user, stripped 
                new_username = request.form.get('username','').strip()
                new_email = request.form.get('email','').strip()
                # if a new username was provided and its different
                if new_username and new_username != user.username:
                    success,msg = update_username(user, new_username) # preform update and validate
                    flash(msg)
                    has_changed = has_changed or success # update flag
                if new_email and new_email != user.email:
                    success,msg = update_email(user, new_email) 
                    flash(msg)
                    has_changed = has_changed or success
            elif 'update_password' in request.form:
                old_password = request.form.get('old_password','')
                new_password = request.form.get('new_password','')
                confirm_password = request.form.get('confirm_password','')
                success,msg = update_password(user, old_password, new_password, confirm_password) # validate + update password
                flash(msg)
                has_changed = has_changed or success
            if has_changed:
                db_session.commit() # save changes to db
            return redirect(url_for('profile')) # redirect to save changes
                
    return render_template('profile.html', user=user)

if __name__ == '__main__':
    app.run(debug=True)

