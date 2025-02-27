"""Added Activate attendance funcion to Admin settings

Revision ID: 1e14bf76b15f
Revises: ef4fe06daa3d
Create Date: 2025-01-16 18:29:15.224431

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '1e14bf76b15f'
down_revision = 'ef4fe06daa3d'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('settings', schema=None) as batch_op:
        batch_op.add_column(sa.Column('allow_attendance', sa.String(length=20), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('settings', schema=None) as batch_op:
        batch_op.drop_column('allow_attendance')

    # ### end Alembic commands ###
