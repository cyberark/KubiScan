
# It is possible to use colorama module but it will require to install this module
'''
\033[  Escape code, this is always the same
0 = Style, 0 for normal.
32 = Text colour, 32 for bright green.
40m = Background colour, 40 is for black.


TEXT COLOUR	CODE	TEXT STYLE	CODE	BACKGROUND COLOUR	CODE
  Black	     30	    No effect	0	     Black	             40
  Red	     31	    Bold	    1	     Red	             41
  Green	     32	    Underline	2	     Green	             42
  Yellow	 33	    Negative1	3	     Yellow	             43
  Blue	     34	    Negative2	5	     Blue	             44
  Purple	 35			  	       		 Purple	             45
  Cyan	     36			  	       		 Cyan	             46
  White	     37			  	       		 White	             47
'''


RED = '\033[0;31;49m'
LIGHTRED = '\033[0;91;49m'
YELLOW = '\033[0;33;49m'
LIGHTYELLOW = '\033[0;93;49m'

WHITE = '\033[0;47;49m'

"""Provide RGB color constants and a colors dictionary with
elements formatted: colors[colorname] = CONSTANT"""

from collections import namedtuple, OrderedDict

Color = namedtuple('RGB', 'red, green, blue')
colors = {}  # dict of colors


class RGB(Color):
    def hex_format(self):
        '''Returns color in hex format'''
        return '#{:02X}{:02X}{:02X}'.format(self.red, self.green, self.blue)


RED1 = RGB(255, 0, 0)
RED2 = RGB(238, 0, 0)
RED3 = RGB(205, 0, 0)
RED4 = RGB(139, 0, 0)

colors['red1'] = RED1
colors['red2'] = RED2
colors['red3'] = RED3
colors['red4'] = RED4

colors = OrderedDict(sorted(colors.items(), key=lambda t: t[0]))
