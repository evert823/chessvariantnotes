from fastapi import APIRouter
from app.models.text_input import TextInput
from app.services.hello_world_service import try_login

router = APIRouter()

@router.post("/trylogin")
def receive_text(input: TextInput):
    return try_login(input)
