import os
import sys
from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()

# User table
class User(Base):
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    email = Column(String(250), nullable=False)
    pw_hash = Column(String(250), nullable=False)
    picture = Column(String(250))

    @property
    def serialize(self):
            """Return object data in easily serializeable format"""
            return {
                'name': self.name,
                'email': self.email,
                'picture': self.picture,
                'id': self.id,
                'pw_hash': self.pw_hash
            }


# Category table
class Category(Base):
    __tablename__ = 'category'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
            'name': self.name,
            'id': self.id,
            'user_id': self.user_id
        }


# MenuItem table
class MenuItem(Base):
    __tablename__ = 'menu_item'

    id = Column(Integer, primary_key=True)
    name = Column(String(80), nullable=False)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)
    category_id = Column(Integer, ForeignKey('category.id'))
    category = relationship(Category)

    description = Column(String(250))
    price = Column(String(8))
    image = Column(String(200))
    kind = Column(String(250))




# This serialize function to be able to send JSON objects in a
# serializable format
    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
           'name': self.name,
           'description': self.description,
           'id': self.id,
           'kind': self.kind,
           'price': self.price,
           'image': self.image,
           'category_id': self.category_id,
           'user_id': self.user_id
        }

engine = create_engine("postgresql://catalogitem:choxutimeo@localhost/tutor")
# engine = create_engine('sqlite:///categorymenu.db')
Base.metadata.create_all(engine)
