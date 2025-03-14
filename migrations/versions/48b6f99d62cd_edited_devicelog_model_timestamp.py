"""Edited DeviceLog model timestamp

Revision ID: 48b6f99d62cd
Revises: 1e14bf76b15f
Create Date: 2025-01-18 18:12:14.883805

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '48b6f99d62cd'
down_revision = '1e14bf76b15f'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('device_log', schema=None) as batch_op:
        batch_op.add_column(sa.Column('timestamp', sa.DateTime(), nullable=True))
        batch_op.drop_column('sign_in_time')

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('device_log', schema=None) as batch_op:
        batch_op.add_column(sa.Column('sign_in_time', sa.DATETIME(), nullable=True))
        batch_op.drop_column('timestamp')

    # ### end Alembic commands ###
