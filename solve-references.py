# -*- coding: utf-8 -*-

#####################################################################################
#
#    Author:  Lukas Schulze
#    Created: 2015-11-01
#    Version: 1.0
#    Website: http://lukas-schulze.de
#
#####################################################################################

import re
import sys

# Pattern to detect base64-encoded UUIDs in XML file
pattern_uuid = re.compile(r'<UUID>([^<]+)</UUID>')
# Pattern to detect hex-encoded UUIDs used in value references
pattern_reference = re.compile(r'\{REF:(P|U)@I:([0-9A-F]+)\}', re.IGNORECASE)
# Pattern to detect the value of username and password fields
pattern_field_value = re.compile(r'<Value[^>]*>([^<]+)</Value>')


# Convert reference string given in HEX to base64
def convert_uuid_to_base64(value):
	return value.decode('hex') .encode('base64')


# Extract username and password of given references from XML tree
def get_credentials_from_references(lines, references, references_set):
	# List of found credentials with tuple (username, password) of given reference in HEX
	credentials = {}
	# valid UUID in HEX
	uuid_found = None
	# username for given UUID
	username_found = None
	# password for given UUID
	password_found = None

	# Line counter for getting values from "next" line which contains the key value for username and password
	line_counter = -1
	for line in lines:
		line_counter += 1

		# No UUID is set
		if uuid_found is None:
			# Line contains a valid UUID
			search = pattern_uuid.search(line)
			if not search:
				uuid_found = None
				continue

			uuid_base64 = search.group(1)

			# Extracted UUID is not in needed references --> continue
			if uuid_base64 not in references_set:
				uuid_found = None
				continue

			# UUID already exists (first one is the latest, following items are history)
			if references[uuid_base64] in credentials:
				uuid_found = None
				continue

			# Reset found variables, continue with next line, because line content already investigated
			uuid_found = references[uuid_base64]
			username_found = None
			password_found = None
			continue

		# No UUID is set --> continue with next line
		if uuid_found is None:
			continue

		# UUID is set and the next line contain the username value
		if '<Key>UserName</Key>' in line:
			search = pattern_field_value.search(lines[line_counter + 1])
			if not search:
				uuid_found = None
				print('Could not extract username for UUID <%s>' % uuid_found)
				exit(1)

			username_found = search.group(1)
			# Username value is a reference -> do not use it
			search = pattern_reference.search(username_found)
			if search:
				uuid_found = None
				continue


		# UUID is set and the next line contain the password value
		if '<Key>Password</Key>' in line:
			search = pattern_field_value.search(lines[line_counter + 1])
			if not search:
				uuid_found = None
				print('Could not extract password for UUID <%s>' % uuid_found)
				exit(1)

			password_found = search.group(1)
			# Password value is a reference -> do not use it
			search = pattern_reference.search(password_found)
			if search:
				uuid_found = None
				continue

		# UUID, username and password were found -> store in credentials dictionary
		if uuid_found is not None and username_found is not None and password_found is not None:
			credentials[uuid_found] = (username_found, password_found)
			uuid_found = None
			username_found = None
			password_found = None

	return credentials


# Call the file with a given filepath to the XML database file
if len(sys.argv) != 2:
	print('ERROR: No file for conversion given!')
	print('    Call the script: $ python solve-references.py /filepath/to/keepass2.xml')
	exit(1)


filepath = sys.argv[1]

# Read complete XML file into variable data
data = ""
try:
	with open(filepath, 'r') as f:
		data = f.read()
except IOError:
	print('Error: Could not find file <%s>' % filepath)
	exit(1)

# Split read data into single lines
lines = data.splitlines()

# Dictionary of used reference UUIDs, key = base64-encoded, value = hex-encoded
references = {}
# Set of used base64-encoded UUIDs
references_set = set()
# Search for all used value references and store them a dictionary and set
for line in lines:
	search = pattern_reference.search(line)
	if search:
		ref_hex = search.group(2)
		ref_hex = ref_hex.strip()
		ref_base64 = convert_uuid_to_base64(ref_hex)
		ref_base64 = ref_base64.strip()
		references[ref_base64] = ref_hex
		references_set.add(ref_base64)


credentials = get_credentials_from_references(lines, references, references_set)

print('%s references found' % len(references))

if len(credentials) != len(references):
	print('ERROR: Number of found credentials does not match number of found references')
	print('    # found credentials: %s' % len(credentials))
	print('    # found references:  %s' % len(references))
	exit(1)

# Replace found credentials with used value references
count_replaces = 0
output = []
for line in lines:
	search = pattern_reference.search(line)
	if search:
		ref_hex = search.group(2)
		if ref_hex not in credentials:
			print('ERROR: Reference to replace does not exist in found credentials')
			print('    Line:             %s' % line.strip())
			print('    Reference HEX:    %s' % ref_hex)
			print('    Reference Base64: %s' % convert_uuid_to_base64(ref_hex))
			exit(1)

		is_username = search.group(1) == 'U'
		if is_username:
			line = pattern_reference.sub(credentials[ref_hex][0], line)
		else:
			line = pattern_reference.sub(credentials[ref_hex][1], line)
		count_replaces += 1

	output.append(line)

print('%s references replaced' % count_replaces)

# Store data with solved references in a new file
with open('%s.solved' % filepath, 'w') as f:
	f.write("\n".join(output))

print('')
print('DONE')