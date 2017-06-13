from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Category, MenuItem, Base, User

engine = create_engine("postgresql://catalogitem:choxutimeo@localhost/tutor")
# engine = create_engine('sqlite:///categorymenu.db')
# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
# A DBSession() instance establishes all conversations with the database
# and represents a "staging zone" for all the objects loaded into the
# database session object. Any change made against the objects in the
# session won't be persisted into the database until you call
# session.commit(). If you're not happy about the changes, you can
# revert all of them back to the last commit by calling
# session.rollback()
session = DBSession()

# Create dummy user
User1 = User(name="Robo Barista", email="tinnyTim@udacity.com",
             picture='https://pbs.twimg.com/profile_images/2671170543/18debd694829ed78203a5a36dd364160_400x400.png',
             pw_hash='Yumvh,cf50e507bb3008d1269f4ea243bfb32962f8607217688cd15d56e2b3b958b0cf')

session.add(User1)
session.commit()

# Create admin user
User2 = User(name="admin", email="admin",
             picture='https://pbs.twimg.com/profile_images/2671170543/18debd694829ed78203a5a36dd364160_400x400.png',
             pw_hash='ygIrS,7c2ff7a0d9edb9a79efad5af40bf88da4b6ceb241a70e98fef3360f0f2cdf734')

session.add(User2)
session.commit()

# Category 1 for Soccer
category1 = Category(user_id=1, name="Soccer")
session.add(category1)
session.commit()

# Item 1 of Category 1
menuItem1 = MenuItem(user_id=1, name="Two shinguards",
                     description="Made of high quality coated vinyl. Heavy "
                     "duty construction to resist tears and punctures. "
                     "E/Z On-Off Velcro. High density padding.",
                     kind="normal", price="18.95",
                     image="https://images-na.ssl-images-amazon.com/images/I/41IeD0VSaVL._AC_US400_QL65_.jpg",
                     category=category1)
session.add(menuItem1)
session.commit()

# Item 2 of Category 1
menuItem2 = MenuItem(user_id=1, name="Singguard",
                     description="Anatomically correct, pull-on design fits "
                     "the contours of your shin for optimal comfort.",
                     kind="sale", price="9.99",
                     image="https://encrypted-tbn3.gstatic.com/images?q=tbn:ANd9GcTVMioY4WRQeRsLJrdjiTQeAztNGGlpYTrypXq6gCaxPcUZqEx7PQ",
                     category=category1)
session.add(menuItem2)
session.commit()

# Item 3 of Category 1
menuItem3 = MenuItem(user_id=1, name="Jersey",
                     description="Authentic Stitching. 100% Polyester Mesh. "
                     "Made in Korea", kind="normal", price="12.90",
                     image="https://images-na.ssl-images-amazon.com/images/I/510CYLztxrL._AC_US400_QL65_.jpg",
                     category=category1)
session.add(menuItem3)
session.commit()

# Item 4 of Category 1
menuItem4 = MenuItem(user_id=1, name="Soccer Cleats",
                     description="Lightweight soccer cleat featuring classic "
                     "center lacing with slim perforated tongue.",
                     kind="normal", price="39.95", image="https://images-na.ssl-images-amazon.com/images/I/41ziwpg0I1L._AC_UL650_SR500,650_QL65_.jpg",
                     category=category1)
session.add(menuItem4)
session.commit()

# Item 5 of Category 1
menuItem5 = MenuItem(user_id=1, name="Sports Soccer Goals",
                     description="Quick shifts between running, walking and "
                     "sprinting are great aerobic exercise", kind="normal",
                     price="24.99", image="https://images-na.ssl-images-amazon.com/images/I/612uvf+CZVL._AC_US400_QL65_.jpg",
                     category=category1)
session.add(menuItem5)
session.commit()

# Item 6 of Category 1
menuItem6 = MenuItem(user_id=1, name="Wilson Soccer Ball",
                     description="Synthetic leather cover extremely soft "
                     "touch and increased durability", kind="normal",
                     price="14.99", image="https://images-na.ssl-images-amazon.com/images/I/415qzk30Z5L._AC_US400_QL65_.jpg",
                     category=category1)
session.add(menuItem6)
session.commit()

# Item 7 of Category 1
menuItem7 = MenuItem(user_id=1, name="Soccer Smarts for Kids",
                     description="Coach Latham has put one in the back of "
                     "the net with a book", kind="new", price="8.49",
                     image="https://images-na.ssl-images-amazon.com/images/"
                     "I/51OGoq8OJaL._AC_US480_FMwebp_QL65_.jpg",
                     category=category1)
session.add(menuItem7)
session.commit()

# Item 8 of Category 1
menuItem8 = MenuItem(user_id=1, name="SKLZ Starkick",
                     description="Develops confidence and strengthens "
                     "kicking, shooting, trapping and throw-in skills",
                     kind="new", price="12.99",
                     image="https://images-na.ssl-images-amazon.com/images/I/512y0XleHXL._AC_US400_FMwebp_QL65_.jpg",
                     category=category1)
session.add(menuItem8)
session.commit()

# Category 2 for Basketball
category2 = Category(user_id=1, name="Basketball")
session.add(category2)
session.commit()

# Item 1 of Category 2
menuItem1 = MenuItem(user_id=1, name="Basketball",
                     description="Designed to withstand the rough-and-tumble "
                     "street game. Wide channel design for excellent grip. "
                     "Features the NBA logo.", kind="normal", price="11.79",
                     image="https://images-na.ssl-images-amazon.com/images/I/61Tdt9jvj0L._AC_US400_QL65_.jpg",
                     category=category2)
session.add(menuItem1)
session.commit()

# Item 2 of Category 2
menuItem2 = MenuItem(user_id=1, name="Hoop",
                     description="Mounts easily to nearly any door. Foam "
                     "padded protective backing", kind="sale", price="14.99",
                     image="https://images-na.ssl-images-amazon.com/images/I/31dz6BPcRTL._AC_US400_QL65_.jpg",
                     category=category2)
session.add(menuItem2)
session.commit()

# Item 3 of Category 2
menuItem3 = MenuItem(user_id=1, name="Portable Set",
                     description="Telescoping mechanism adjusts from 7.5 to "
                     "10-Feet 6-Inch increments", kind="normal",
                     price="109.00", image="https://images-na.ssl-images-amazon.com/images/I/51X7OLkit6L._AC_US400_QL65_.jpg",
                     category=category2)
session.add(menuItem3)
session.commit()

# Item 4 of Category 2
menuItem4 = MenuItem(user_id=1, name="Mini Basketball Hoop",
                     description="Easily mounts with a pre-assembled bracket "
                     "and over the Door Foam Padded Bracket", kind="normal",
                     price="24.99", image="https://images-na.ssl-images-amazon.com/images/I/411Dd84D3uL._AC_US400_QL65_.jpg",
                     category=category2)
session.add(menuItem4)
session.commit()

# Item 5 of Category 2
menuItem5 = MenuItem(user_id=1, name="Lifetime Classic Basketball Rim",
                     description="Includes 50g all-weather net and hardware",
                     kind="normal", price="31.98",
                     image="https://images-na.ssl-images-amazon.com/images/I/41NHsm26bKL._AC_US400_QL65_.jpg",
                     category=category2)
session.add(menuItem5)
session.commit()

# Item 6 of Category 2
menuItem6 = MenuItem(user_id=1, name="Spalding Heavy Duty Basketball Net",
                     description="Heavy duty net in red/white/blue",
                     kind="normal", price="11.45",
                     image="https://images-na.ssl-images-amazon.com/images/I/41yfWDFTaJL._AC_US400_QL65_.jpg",
                     category=category2)
session.add(menuItem6)
session.commit()

# Item 7 of Category 2
menuItem7 = MenuItem(user_id=1, name="Miracol Dual Action Ball Pump",
                     description="Best for Basketball, Soccer, Volleyball, "
                     "Rugby & Other Inflatables", kind="normal",
                     price="12.49", image="https://images-na.ssl-images-ama"
                     "zon.com/images/I/41Notdbx6nL._AC_US480_FMwebp_QL65_.jpg",
                     category=category2)
session.add(menuItem7)
session.commit()

# Item 8 of Category 2
menuItem8 = MenuItem(user_id=1, name="Basketball Shorts for Men",
                     description="Mesh Design Activewear with Side Pockets",
                     kind="new", price="9.99",
                     image="https://images-na.ssl-images-amazon.com/images/I/41XEGleTV7L._AC_US500_QL65_.jpg",
                     category=category2)
session.add(menuItem8)
session.commit()

# Category 3 for Baseball
category3 = Category(user_id=1, name="Baseball")
session.add(category3)
session.commit()

# Item 1 of Category 3
menuItem1 = MenuItem(user_id=1, name="Bat",
                     description="Nimble, lighter weight of ash and its "
                     "overall give make for a truly powerful bat with a larger"
                     "and more flexible sweet spot.", kind="normal", price="14.95",
                     image="https://images-na.ssl-images-amazon.com/images/I/31ePOqYMm2L._AC_US400_QL65_.jpg",
                     category=category3)
session.add(menuItem1)
session.commit()

# Item 2 of Category 3
menuItem2 = MenuItem(user_id=1, name="Bat Bag",
                     description="Durable Wheeled Bag. Easton Product. Great "
                     "for players of all caliber. Structural Piping to "
                     "Maximum volume.", kind="normal", price="14.95",
                     image="https://images-na.ssl-images-amazon.com/images/I/41idiTcaFgL._AC_US400_QL65_.jpg",
                     category=category3)
session.add(menuItem2)
session.commit()

# Item 3 of Category 3
menuItem3 = MenuItem(user_id=1, name="Baseball",
                     description="Official size 9 inches. Weight 5 oz. "
                     "Synthetic cover. Solid cork & rubber center.",
                     kind="sale", price="6.33",
                     image="https://images-na.ssl-images-amazon.com/images/I/51VGMBD3NYL._AC_US400_QL65_.jpg",
                     category=category3)
session.add(menuItem3)
session.commit()

# Item 4 of Category 3
menuItem4 = MenuItem(user_id=1, name="Franklin MLB Pitching Machine",
                     description="Height adjustment for pitches. Ball pitches "
                     "every 10 seconds", kind="normal", price="28.49",
                     image="https://images-na.ssl-images-amazon.com/images/I/41HsG5GHPPL._AC_US400_QL65_.jpg",
                     category=category3)
session.add(menuItem4)
session.commit()

# Item 5 of Category 3
menuItem5 = MenuItem(user_id=1, name="Crazy Catch Wild Child 2.0 Double",
                     description="Insane rebound net sends ball back in "
                     "unpredictable directions", kind="normal", price="139",
                     image="https://images-na.ssl-images-amazon.com/images/I/61vxAAWOdZL._AC_US400_QL65_.jpg",
                     category=category3)
session.add(menuItem5)
session.commit()

# Item 6 of Category 3
menuItem6 = MenuItem(user_id=1, name="Nexxgen Apparel Compression",
                     description="40 Styles and Colors- Men, Women, Youth",
                     kind="normal", price="5.49",
                     image="https://images-na.ssl-images-amazon.com/images/I/31JUOb5lNFL._AC_US400_QL65_.jpg",
                     category=category3)
session.add(menuItem6)
session.commit()

# Item 7 of Category 3
menuItem7 = MenuItem(user_id=1, name="Mens or Youth Sleeve",
                     description="Mens or Youth 3/4 Sleeve Baseball Tee Shirts"
                     "Youth S to Adult 4X", kind="new", price="6.95",
                     image="https://images-na.ssl-images-amazon.com/images/I/415MTZmGhpL._AC_US400_QL65_.jpg",
                     category=category3)
session.add(menuItem7)
session.commit()

# Item 8 of Category 3
menuItem8 = MenuItem(user_id=1, name="Recreational Baseball Bundles",
                     description="Baseballs come in a reusable mesh bag with "
                     "drawstring", kind="new", price="25.31",
                     image="https://images-na.ssl-images-amazon.com/images/I/61avrL8lEjL._AC_US400_QL65_.jpg",
                     category=category3)
session.add(menuItem8)
session.commit()


# Category 4 for Frisbee
category4 = Category(user_id=1, name="Frisbee")
session.add(category4)
session.commit()

# Item 1 of Category 4
menuItem1 = MenuItem(user_id=1, name="Flying Disc",
                     description="The Nite Ize Flashflight LED Light Up "
                     "Flying Disc is suitable for serious sport",
                     kind="normal", price="14.99",
                     image="https://images-na.ssl-images-amazon.com/images/I/41gb6AuDqkL._AC_US400_QL65_.jpg",
                     category=category4)
session.add(menuItem1)
session.commit()

# Item 2 of Category 4
menuItem2 = MenuItem(user_id=1, name="Ultimate Disc",
                     description="Best choice for: Ultimate, Goaltimate, "
                     "Freestyle, days at the beach.", kind="normal", price="9.72",
                     image="https://images-na.ssl-images-amazon.com/images/I/51UeTBj03QL._AC_US400_QL65_.jpg",
                     category=category4)
session.add(menuItem2)
session.commit()

# Item 3 of Category 4
menuItem3 = MenuItem(user_id=1, name="Sport Disc",
                     description="Freestyle Players Association hails "
                     "Sky-Styler as the best freestyle disc ever made",
                     kind="normal", price="9.13",
                     image="https://images-na.ssl-images-amazon.com/images/I/41gOYcNyAIL._AC_US400_QL65_.jpg",
                     category=category4)
session.add(menuItem3)
session.commit()

# Item 4 of Category 4
menuItem4 = MenuItem(user_id=1, name="Aerobie Pro Ring",
                     description="Soft rubber edges for comfortable catches. "
                     "Patented high performance design. Perfect for backyard, "
                     "park or field. Thrilling game of catch for 2 or more "
                     "players.Single unit", kind="new", price="9.89",
                     image="https://images-na.ssl-images-amazon.com/images/I/51cUUF3+xuL._AC_US400_QL65_.jpg",
                     category=category4)
session.add(menuItem4)
session.commit()

# Category 5 for Snowboarding
category5 = Category(user_id=1, name="Snow Boarding")
session.add(category5)
session.commit()

# Item 1 of Category 5
menuItem1 = MenuItem(user_id=1, name="Goggles",
                     description="Work great as cycling, mountain climbing, "
                     "skiing, sports glasses.", kind="normal", price="6.59",
                     image="https://images-na.ssl-images-amazon.com/images/I/51+j7CFAqZL._AC_US400_QL65_.jpg",
                     category=category5)
session.add(menuItem1)
session.commit()

# Item 2 of Category 5
menuItem2 = MenuItem(user_id=1, name="Snowboard",
                     description="Beginner snowboard is great choice to "
                     "introduce kids to snowboarding in backyard or on nearby "
                     "sledding hill.", kind="normal", price="43.46",
                     image="https://images-na.ssl-images-amazon.com/images/I/411gRJVNmOL._AC_US400_QL65_.jpg",
                     category=category5)
session.add(menuItem2)
session.commit()

# Item 3 of Category 5
menuItem3 = MenuItem(user_id=1, name="Snowboard Socks",
                     description="Drystat combined with Micro Supreme "
                     "materials creates an environmental atmosphere where "
                     "flesh meets fiber keeping your feet dry.",
                     kind="new", price="12.96",
                     image="https://images-na.ssl-images-amazon.com/images/I/41o7V2wUjpL._AC_US500_QL65_.jpg",
                     category=category5)
session.add(menuItem3)
session.commit()


# Category 6 for Rock Climbing
category6 = Category(user_id=1, name="Rock Climbing")
session.add(category6)
session.commit()

# Item 1 of Category 6
menuItem1 = MenuItem(user_id=1, name="Safe Seat Belt",
                     description="One size fit all. 23 kN-rated belay and haul loops.",
                     kind="normal", price="52.99",
                     image="https://images-na.ssl-images-amazon.com/images/I/51PDzCgdjkL._AC_US400_QL65_.jpg",
                     category=category6)
session.add(menuItem1)
session.commit()

# Item 2 of Category 6
menuItem2 = MenuItem(user_id=1, name="Momentum Harness",
                     description="Pre-threaded Speed Adjust waistbelt buckle. "
                     "Bullhorn-shaped waistbelt built using Dual Core "
                     "Construction.", kind="new", price="44.96",
                     image="https://images-na.ssl-images-amazon.com/images/I/517Im+r6anL._AC_US400_QL65_.jpg",
                     category=category6)
session.add(menuItem2)
session.commit()

# Item 3 of Category 6
menuItem3 = MenuItem(user_id=1, name="Chalk Bag",
                     description="Zippered pocket on the front, to keep your "
                     "money, ID, ring with you while climbing.", kind="new", price="12.95",
                     image="https://images-na.ssl-images-amazon.com/images/I/51Y+GD0OBuL._AC_US400_QL65_.jpg",
                     category=category6)
session.add(menuItem3)
session.commit()

# Category 7 for Foosball
category7 = Category(user_id=1, name="Foosball")
session.add(category7)
session.commit()

# Item 1 of Category 7
menuItem1 = MenuItem(user_id=1, name="Hathaway Soccer Table",
                     description="Playing Surface: 40.5 in. L x 23 in. W x 1/4"
                     "in. thick MDF", kind="normal", price="122.99",
                     image="https://images-na.ssl-images-amazon.com/images/I/51jcaSeAbaL._AC_US400_QL65_.jpg",
                     category=category7)
session.add(menuItem1)
session.commit()

# Item 2 of Category 7
menuItem2 = MenuItem(user_id=1, name="American Legend Charger Table",
                     description="Abacus-Style Scoring. Internal Ball Return "
                     "System. 1/2 inches Hollow Rods with Chrome Finish.",
                     kind="normal", price="174.99",
                     image="https://images-na.ssl-images-amazon.com/images/I/41JqQpZmsRL._AC_US400_QL65_.jpg",
                     category=category7)
session.add(menuItem2)
session.commit()

# Item 3 of Category 7
menuItem3 = MenuItem(user_id=1, name="Black and White Soccer Balls",
                     description="HOURS OF FUN - Enjoy many games of table "
                     "soccer without worrying about losing another foosball!.",
                     kind="new", price="9.99", image="https://images-na.ssl"
                     "-images-amazon.com/images/I/51fpVqQY7BL._AC_US400_FMwebp"
                     "_QL65_.jpg", category=category7)
session.add(menuItem3)
session.commit()


# Category 8 for Skating
category8 = Category(user_id=1, name="Skating")
session.add(category8)
session.commit()

# Item 1 of Category 8
menuItem1 = MenuItem(user_id=1, name="Adjustable Inline Skate",
                     description="Man Made. Boot: Soft boot support system "
                     "with dual cam-lever buckle, push button adjustment "
                     "system, and comfort fit padding.", kind="normal", price="34.83",
                     image="https://images-na.ssl-images-amazon.com/images/I/51NqaZyQDgL._AC_US400_QL65_.jpg",
                     category=category8)
session.add(menuItem1)
session.commit()

# Item 2 of Category 8
menuItem2 = MenuItem(user_id=1, name="Polartec Polar Fleece Pants",
                     description="Fleece. Made in USA. Comfortable next-to-"
                     "skin. 4-way stretch.", kind="normal", price="44.99",
                     image="https://images-na.ssl-images-amazon.com/images/I/31ZGxddw9xL._AC_US400_QL65_.jpg",
                     category=category8)
session.add(menuItem2)
session.commit()

# Item 3 of Category 8
menuItem3 = MenuItem(user_id=1, name="Ice Skating",
                     description="Nylex lining for warmth, comfort and "
                     "durability", kind="new", price="64.95",
                     image="https://images-na.ssl-images-amazon.com/images/I/41OV8QZyG4L._AC_US400_QL65_.jpg",
                     category=category8)
session.add(menuItem3)
session.commit()

# Category 9 for Hockey
category9 = Category(user_id=1, name="Hockey")
session.add(category9)
session.commit()

# Item 1 of Category 9
menuItem1 = MenuItem(user_id=1, name="Folding Hockey Goal Set",
                     description="Street hockey set includes two 43-inch Jet "
                     "Flo sticks, one no-bounce hockey ball, and a goal.",
                     kind="normal", price="23.99",
                     image="https://images-na.ssl-images-amazon.com/images/I/51cKcs6NofL._AC_US400_FMwebp_QL65_.jpg",
                     category=category9)
session.add(menuItem1)
session.commit()

# Item 2 of Category 9
menuItem2 = MenuItem(user_id=1, name="Cushioned Crew Socks",
                     description="Poly/Nylon Moisture Wicking Blend",
                     kind="normal", price="9.99",
                     image="https://images-na.ssl-images-amazon.com/images/I/41NRA-N3sjL._AC_US500_FMwebp_QL65_.jpg",
                     category=category9)
session.add(menuItem2)
session.commit()

# Item 3 of Category 9
menuItem3 = MenuItem(user_id=1, name="ABS Blade Stick",
                     description="High impact ABS blade and multiply birch "
                     "shaft. 87 Flex P92 Curve. Right Handed", kind="new", price="29.99",
                     image="https://images-na.ssl-images-amazon.com/images/I/31QbyDqC9QL._AC_US400_QL65_.jpg",
                     category=category9)
session.add(menuItem3)
session.commit()

print "added menu items!"