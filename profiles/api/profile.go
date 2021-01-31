package api

type Profile struct {
  Firstname string    `json:"firstName"`
  Lastname  string    `json:"lastName"`
  Email     string    `json:"email"`
  UUID      string    `json:"uuid"`
}
