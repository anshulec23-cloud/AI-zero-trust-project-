"""Initial schema

Revision ID: 89c877d9e697
Revises: 
Create Date: 2026-07-10 03:43:36.840633

"""
from typing import Sequence ,Union 

from alembic import op 
import sqlalchemy as sa 



revision :str ='89c877d9e697'
down_revision :Union [str ,None ]=None 
branch_labels :Union [str ,Sequence [str ],None ]=None 
depends_on :Union [str ,Sequence [str ],None ]=None 


def upgrade ()->None :

    pass 



def downgrade ()->None :

    pass 

