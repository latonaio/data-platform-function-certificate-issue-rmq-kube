package dpfm_api_input_reader

type SDC struct {
	ConnectionKey     string   `json:"connection_key"`
	Result            bool     `json:"result"`
	RedisKey          string   `json:"redis_key"`
	Filepath          string   `json:"filepath"`
	APIStatusCode     int      `json:"api_status_code"`
	RuntimeSessionID  string   `json:"runtime_session_id"`
	BusinessPartnerID *int     `json:"business_partner"`
	ServiceLabel      string   `json:"service_label"`
	APIType           string   `json:"APIType"`
	Message           Message  `json:"message"`
	APISchema         string   `json:"api_schema"`
	Accepter          []string `json:"accepter"`
	Deleted           bool     `json:"deleted"`
}

type Message struct {
	ItemForX509 []ItemForX509 `json:"ItemsForX509"`
}

type ItemForX509 struct {
	SerialNumber           string `json:"SerialNumber"`
	CountryName            string `json:"CountryName"`
	StateOrProvinceName    string `json:"StateOrProvinceName"`
	LocalityName           string `json:"LocalityName"`
	OrganizationName       string `json:"organizationName"`
	OrganizationalUnitName string `json:"organizationalUnitName"`
	EmailAddress           string `json:"EmailAddress"`
	SubjectAltName         string `json:"SubjectAltName"`
	ExpiredDate            string `json:"ExpiredDate"`
}
