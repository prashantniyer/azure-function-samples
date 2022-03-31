import ctypes, os, json, subprocess # Subprocess is imported to make sure it is hooked
libtw = None
# load_twistlock loads the twistlock libtw library and adds an interface for wrapping handlers
def load_twistlock(path):
	global libtw
	path += '/twistlock/libtw_serverless.so'
	if not os.path.exists(path):
		return False
	# Load twistlock shared object
	libtw = ctypes.CDLL(path, mode = ctypes.RTLD_LOCAL)
	# Check handler request should be exported from the shared object, receives 2 strings:
	# -event - the event json
	# -context - the function json containing the aws request ID and invoked function ARN
	# with their length and returns a boolean
	libtw.check_request.argtypes=[ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_int]
	libtw.check_request.restype=ctypes.c_bool
	return True

#  wrap_handler returns a function that wraps the original handler
def wrap_handler(original_handler):
	# twistlock_handler checks handler input for attacks and calls the original handler
	def twistlock_handler(event, context):
		# Checks handler input for attacks and calls the original handler
		json_event = json.dumps(event).encode('utf-8')
		# context isn't serializable, extracting required fields
		# ref: https://docs.aws.amazon.com/lambda/latest/dg/python-context-object.html
		function_context = {}
		function_context['AwsRequestID'] = context.aws_request_id
		function_context['InvokedFunctionArn'] = context.invoked_function_arn
		json_context = json.dumps(function_context).encode('utf-8')
		# Check request returns whether to block or approve the request
		if libtw.check_request(ctypes.create_string_buffer(json_event), len(json_event), ctypes.create_string_buffer(json_context), len(json_context)):
			response = None
			# Ignore all errors that relate to custom response
			try:
				response = json.loads(os.environ['TW_CUSTOM_RESPONSE'])
			except:
				None
			return response
		return original_handler(event, context)
	return twistlock_handler

# If twistlock layer is used, the shared object will be in /opt, otherwise in the folder saved in LAMBDA_TASK_ROOT
# Refs:
# https://docs.aws.amazon.com/lambda/latest/dg/current-supported-versions.html
# https://docs.aws.amazon.com/lambda/latest/dg/configuration-layers.html
if not load_twistlock(os.environ['LAMBDA_TASK_ROOT']) and not load_twistlock('/opt'):
	raise ValueError('[Twistlock] Failed to find Twistlock runtime')


def handler(original_handler):
	return wrap_handler(original_handler)
