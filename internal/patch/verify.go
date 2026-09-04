package patch

import (
	"fmt"

	xpe "github.com/unxed/go2xp/internal/pe"
)

// Verify перечитывает пропатченный файл и проверяет инварианты для профиля.
func Verify(path, profilePath string) error {
	prof, err := LoadProfile(profilePath)
	if err != nil {
		return err
	}
	info, err := xpe.Open(path)
	if err != nil {
		return err
	}
	var problems []string
	if info.OSMajor != prof.OSMajor || info.OSMinor != prof.OSMinor {
		problems = append(problems, fmt.Sprintf("OS version %d.%d != profile %d.%d", info.OSMajor, info.OSMinor, prof.OSMajor, prof.OSMinor))
	}
	if info.SubsysMajor != prof.SubsystemMajor || info.SubsysMinor != prof.SubsystemMinor {
		problems = append(problems, fmt.Sprintf("subsystem version %d.%d != profile %d.%d", info.SubsysMajor, info.SubsysMinor, prof.SubsystemMajor, prof.SubsystemMinor))
	}
	if info.DllCharacteristics&0x0040 != 0 {
		problems = append(problems, "DYNAMIC_BASE still set")
	}
	// в таблице импорта не должно остаться отсутствующих на целевой ОС функций
	ownSlot := map[uint32]bool{}
	hookReady := map[string]bool{} // dll!func -> есть полифилл-хук
	for _, e := range info.Table {
		if e.OwnSlot != 0 {
			ownSlot[e.OwnSlot] = true
		}
		if e.Polyfill != 0 {
			hookReady[e.DLL+"!"+e.Func] = true
		}
	}
	for _, im := range info.Imports {
		if ownSlot[info.ImageBase+im.SlotRVA] {
			continue
		}
		if prof.missing(im.DLL, im.Name) {
			problems = append(problems, fmt.Sprintf("still imports missing %s!%s", im.DLL, im.Name))
		}
		if forceHook(im.DLL, im.Name) && hookReady[im.DLL+"!"+im.Name] {
			problems = append(problems, fmt.Sprintf("runtime %s!%s still in import table (should be hooked)", im.DLL, im.Name))
		}
	}
	if len(problems) > 0 {
		for _, p := range problems {
			fmt.Println("  FAIL:", p)
		}
		return fmt.Errorf("%d verification problem(s)", len(problems))
	}
	return nil
}
