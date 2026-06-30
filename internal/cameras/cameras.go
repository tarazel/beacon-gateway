package cameras

type Camera struct {
	ID          string `json:"id"`
	DisplayName string `json:"display_name"`
	Stream      string `json:"stream"`
}

type Registry struct {
	byID map[string]Camera
	list []Camera
}

func NewRegistry(cams []Camera) *Registry {
	r := &Registry{
		byID: make(map[string]Camera, len(cams)),
		list: make([]Camera, 0, len(cams)),
	}
	for _, c := range cams {
		if c.ID == "" || c.Stream == "" {
			continue
		}
		r.byID[c.ID] = c
		r.list = append(r.list, c)
	}
	return r
}

func (r *Registry) Get(id string) (Camera, bool) {
	c, ok := r.byID[id]
	return c, ok
}

func (r *Registry) List() []Camera {
	out := make([]Camera, len(r.list))
	copy(out, r.list)
	return out
}
