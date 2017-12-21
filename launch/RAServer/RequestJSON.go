package main

// Attribute is a name and value pair
type Attribute struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// RegistrationRequest for a new identity
type RegistrationRequest struct {
	// Name is the unique name of the identity
	Name string `json:"id" help:"Unique name of the identity"`

	// Secret is an optional password.  If not specified,
	// a random secret is generated.  In both cases, the secret
	// is returned in the RegistrationResponse.
	Secret string `json:"secret" help:"The enrollment secret for the identity being registered"`

	// Attributes associated with this identity
	Attributes []Attribute `json:"attrs,omitempty"`

}


type enrollmentResponseNet struct {
	// Base64 encoded PEM-encoded ECert
	Cert string `json:"cert"`
	// The private key PEM-encoded
	Key string `json:"key"`
}

// ResponseMessage implements the standard for response errors and
// messages. A message has a code and a string message.
type ResponseMessage struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Response implements the CloudFlare standard for API
// responses.
type Response struct {
	Success  bool              `json:"success"`
	Result   enrollmentResponseNet       `json:"result"`
	Errors   []ResponseMessage `json:"errors"`
}