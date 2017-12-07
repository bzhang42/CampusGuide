We started out with an idea: a website where students can rate locations like study spots and restaurants all across Harvard campus,
such that the results could be compiled into a resource for future generations of students to reference. A few sketches and
whiteboard scribbles later, we decided the project would have two main components: data collection and web design.

The data collection was first. A database was created with tables storing location information, different labels such as "Date Spot"
and "Study Spot", user and account information, and historical data of user ratings. We decided on fifteen different labels, as
well as seven fundamental criteria that would distinguish these locations. Over the course of our data collection, the database
would fill up with over 350 locations across campus, and over 700 tags would be created. Images were stored as HTML elements for
ease of reference, and we eventually decided to add a wishes table to represent users' wishlists (lists of locations they'd like to
visit but haven't yet).

As we approached the website itself, we began with the CS50 Finance template, but we quickly diverged as we dynamically generated
locations and rating pages. Throughout, however, we stuck to the trifecta of HTML, CSS and Javascript to code the website, so as to
boost our experience with these languages. We  programmed each location page to display unique information, and to have a form with two
submit buttons. We explored column design and image borders/padding, as well as modified the CSS of the navigation bar and buttons
quite a bit. For the rating pages, we used images of emojis and sliders to facilitate easy user interactions, and dynamically
generated the questions based on the tags associated with the location. Upon submitting a rating, we programmed the website to
insert the rating into the appropriate table, as well as to update the location's aggregate ratings along a formula which gave
greater weight to more recent ratings (this required quite a bit of tinkering with datetime).

Next, we approached the home page, which we decided would begin with the elements of a rating page for a random Harvard location
that included a submission form, and then go on to display several column-aligned tables beneath of top campus locations in various
categories. The purpose of this was to ensure that users could easily rate locations, one after the other, and therefore
contribute to our database of locations and ratings. We used unique formulas that weighed different criteria differently for
calculating each location's rating under each category, then listed the top five locations in the tables, as well as dynamically
hyperlinking them to their respective location pages.

Along the way, we decided to add search bar functionality with a drop down menu, as well as email confirmation and change password
features to the website (to ensure only Harvard students could make accounts). We also altered the navigation tabs to include
a description of the co-founders (us!), as well as to include a profile icon that redirects to a profile page, and an account
dropdown menu that redirects to an accounts page, or to logging out. We decided that the profile page would display the user's
number of ratings, as well as join date and their wishlist, a scrollable table which draws from the wishes table in the database.

Towards the end, we added flash alerts for form submissions, as well as altered some of the CS50 Apology htmls to be a bit more
rivalrous, to say the least (yuck fale!). We also modified the pages that required logins so that anonymous users could access
the home page and rate random locations, but would have to log in to access location pages or any other tabs. We chose a crimson
color scheme, made the navigation pane sticky, and inserted a beautiful background photo taken by yours truly in select pages of
the website.

Finally, we thought that releasing this project to the public would inevitably lead to students suggesting locations we had
forgotten, so we added a suggestions page where students can send in their suggestions of locations to include. We attempted to
host this on Heroku before the deadline and successfully got the website up and running, but soon realized that the PostgreSQL
structure diverged from sqlite, meaning we'd have to restructure our database and change all of our code, so that will be a step we
take after the deadline.

Overall, this project was entirely hand-coded, and taught us a ton about the intricacies of HTML, CSS, Javascript, most
of which is impossible to list out here but which is obvious in our code. We're both excited to continue pursuing this project into
winter break and the upcoming semester(s), to try and make our vision a reality: useful and up-to-date information on the best
places on campus for students, new and old, for years to come.