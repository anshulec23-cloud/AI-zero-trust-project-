"""Add device_states table

Revision ID: f1a4571c083c
Revises: 89c877d9e697
Create Date: 2026-07-10 17:12:45.907856

"""
from typing import Sequence ,Union 

from alembic import op 
import sqlalchemy as sa 



revision :str ='f1a4571c083c'
down_revision :Union [str ,None ]='89c877d9e697'
branch_labels :Union [str ,Sequence [str ],None ]=None 
depends_on :Union [str ,Sequence [str ],None ]=None 


def upgrade ()->None :

    op .create_table ('device_states',
    sa .Column ('id',sa .Integer (),nullable =False ),
    sa .Column ('device_id',sa .String (length =50 ),nullable =False ),
    sa .Column ('is_isolated',sa .Boolean (),nullable =True ),
    sa .Column ('updated_at',sa .DateTime (),nullable =True ),
    sa .PrimaryKeyConstraint ('id'),
    sa .UniqueConstraint ('device_id')
    )



def downgrade ()->None :

    op .drop_table ('device_states')

