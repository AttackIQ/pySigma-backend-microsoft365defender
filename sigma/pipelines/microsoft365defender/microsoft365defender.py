from typing import Optional

from sigma.processing.pipeline import ProcessingPipeline

from ..microsoftxdr import microsoft_xdr_pipeline


def microsoft_365_defender_pipeline(
    transform_parent_image: Optional[bool] = True, query_table: Optional[str] = None
) -> ProcessingPipeline:
    """DEPRECATED: Use microsoft_xdr_pipeline instead."""
    return microsoft_xdr_pipeline(
        transform_parent_image=transform_parent_image, query_table=query_table
    )
