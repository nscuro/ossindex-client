package ossindex

type Cache interface {
	Add(reports []ComponentReport) error
	Get(coordinates []string) (map[string]ComponentReport, error)
	Remove(coordinates []string) error
	Clean() error
}

type NoOpCache struct {
}

func (n NoOpCache) Add(_ []ComponentReport) error {
	return nil
}

func (n NoOpCache) Get(_ []string) (map[string]ComponentReport, error) {
	return nil, nil
}

func (n NoOpCache) Remove(_ []string) error {
	return nil
}

func (n NoOpCache) Clean() error {
	return nil
}
