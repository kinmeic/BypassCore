package errors

import "context"

// PrintNonRemovalDeprecatedFeatureWarning prints a warning of a deprecated feature.
func PrintNonRemovalDeprecatedFeatureWarning(sourceFeature string, targetFeature string) {
	LogWarning(context.Background(), "The feature "+sourceFeature+" is deprecated, not recommended for using and might be removed. Please migrate to "+targetFeature+" as soon as possible.")
}

// PrintDeprecatedFeatureWarning prints a warning for a deprecated and going to be removed feature.
func PrintDeprecatedFeatureWarning(feature string, migrateFeature string) {
	if len(migrateFeature) > 0 {
		LogWarning(context.Background(), "This feature "+feature+" is deprecated, will be removed soon and being migrated to "+migrateFeature+". Please update your config(s) according to release note and documentation before removal.")
	} else {
		LogWarning(context.Background(), "This feature "+feature+" is deprecated and will be removed soon. Please update your config(s) according to release note and documentation before removal.")
	}
}

// PrintRemovedFeatureError prints an error message for a removed feature then returns an error.
func PrintRemovedFeatureError(feature string, migrateFeature string) error {
	if len(migrateFeature) > 0 {
		return New("The feature " + feature + " has been removed and migrated to " + migrateFeature + ". Please update your config(s) according to release note and documentation.")
	}
	return New("The feature " + feature + " has been removed. Please update your config(s) according to release note and documentation.")
}
