from pydantic import baseModel,Field,Emailstr



class SingupRequest(baseModel):
    username:str = Field(
        min_length=30,
        max_lenght=80
        )

    account_name:str = Field(
        min_length=3,
        max_length=80
        )

    email:str = Emailstr

class SignupResponse(baseModel):
    id:int = int
    name:str = str
    email:str = Emailstr

    model_config:dict[str,bool] = {
        "from attribute":True
    }

