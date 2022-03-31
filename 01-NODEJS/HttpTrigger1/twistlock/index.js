const serverless = require('./serverless');

// checkRequest checks if the request has a malicious event
let checkRequest = (event, context) => {
	// ref: https://docs.aws.amazon.com/lambda/latest/dg/nodejs-prog-model-context.html
	let functionContext = {};
	functionContext['AwsRequestID'] = context.awsRequestId;
	functionContext['InvokedFunctionArn'] = context.invokedFunctionArn;
	return serverless.check_request(JSON.stringify(event), JSON.stringify(functionContext));
};

// preventResponse returns response for prevent based on custom response or null else
let preventResponse = () => {
	let customResponse = process.env.TW_CUSTOM_RESPONSE;
	let response = null;
	if (customResponse) {
		// ignore custom response errors
		try {
			response = JSON.parse(customResponse);
		} catch (ex) {}
	}
	return response;
};

// handler for non-async functions
let wrapHandler = (originalHandler) => {
	return (event, context, callback) => {
		if (checkRequest(event, context)) {
			if (callback) {
				callback(null, preventResponse());
			}
		} else {
			return originalHandler(event, context, callback);
		}
	};
};

// handler for async functions
let wrapAsyncHandler = (originalHandler) => {
	return async (event, context) => {
		if (checkRequest(event, context)) {
			return Promise.resolve(preventResponse());
		}
		return await originalHandler(event, context);
	};
};

// handler for non-async functions
exports.handler = wrapHandler;

// handler for async functions
exports.asyncHandler = wrapAsyncHandler;
