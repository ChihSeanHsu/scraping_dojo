from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import HTMLResponse, Response
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
import uuid


fake_users_db = {
    "testuser": {
        "username": "testuser",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        "hashed_password": "fakehashedpassword",
        "disabled": False,
    },
    "alice": {
        "username": "alice",
        "full_name": "Alice Wonderson",
        "email": "alice@example.com",
        "hashed_password": "fakehashedsecret2",
        "disabled": True,
    },
}

app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
templates = Jinja2Templates(directory="templates/")
app.mount("/static", StaticFiles(directory="static"), name="static")
valid_token = dict()

def fake_hash_password(password: str):
    return "fakehashed" + password


class User(BaseModel):
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    disabled: Optional[bool] = None


class UserInDB(User):
    hashed_password: str


def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)


def fake_decode_token(token):
    # This doesn't provide any security at all
    # Check the next version
    
    user = get_user(fake_users_db, token)
    return user


async def get_current_user(token: str = Depends(oauth2_scheme)):
    if token not in valid_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials no token",
            headers={"Authorization": "Bearer"},
        )
    user_key = valid_token[token]
    # user = fake_decode_token(user_key)
    # if not user:
    #     raise HTTPException(
    #         status_code=status.HTTP_401_UNAUTHORIZED,
    #         detail="Invalid authentication credentials no user",
    #         headers={"Authorization": "Bearer"},
    #     )
    return user_key


async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

@app.get("/secret/", response_class=HTMLResponse)
async def secret(request: Request, current_user: User = Depends(get_current_active_user)):
    
    return """
    <html>
    <head>
        <title>Some HTML in here</title>
    </head>
    <body>
        <div>
        Here is secret page!!
        https://bit.ly/3JaylY4
        </div>
    </body>
</html>
    """

@app.get("/")
async def login(request: Request):
    return  templates.TemplateResponse('login.html', context={"request": request})
    
@app.get("/test/", response_class=HTMLResponse)
async def test(request: Request, current_user: User = Depends(get_current_active_user)):
    
    return """
    <html>
    <head>
        <title>Some HTML in here</title>
    </head>
    <body>
        <div>
        you almost doen
        </div>
    </body>
</html>
    """

@app.post("/token",response_class=HTMLResponse)
async def login(response: Response, form_data: OAuth2PasswordRequestForm = Depends()):
    user_dict = fake_users_db.get(form_data.username)
    if not user_dict:
        raise HTTPException(status_code=400, detail="Incorrect username")
    user = UserInDB(**user_dict)
    hashed_password = fake_hash_password(form_data.password)
    if not hashed_password == user.hashed_password:
        raise HTTPException(status_code=400, detail="Incorrect password")
    
    token = uuid.uuid4().hex
    valid_token[token] = user
    {"access_token": token, "token_type": "bearer"}
    response.headers["Authorization"] = f"Bearer {token}"
    response.set_cookie(key="session", value=token)
    return """
    <html>
    <head>
        <title>Some HTML in here</title>
    </head>
    <body>
        <div>
        success
        </div>
    </body>
</html>
    """
